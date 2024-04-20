/*
 * network_iptables.c: iptables-based firewall implementation for
 *                     virtual networks.
 *
 * Copyright (C) 2007-2014 Red Hat, Inc.
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

#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "internal.h"
#include "virfirewalld.h"
#include "virerror.h"
#include "virlog.h"
#include "virhash.h"
#include "virenum.h"
#include "network_iptables.h"

VIR_LOG_INIT("network.iptables");

#define VIR_FROM_THIS VIR_FROM_NONE

#define VIR_IPTABLES_INPUT_CHAIN "LIBVIRT_INP"
#define VIR_IPTABLES_OUTPUT_CHAIN "LIBVIRT_OUT"
#define VIR_IPTABLES_FWD_IN_CHAIN "LIBVIRT_FWI"
#define VIR_IPTABLES_FWD_OUT_CHAIN "LIBVIRT_FWO"
#define VIR_IPTABLES_FWD_X_CHAIN "LIBVIRT_FWX"
#define VIR_IPTABLES_NAT_POSTROUTE_CHAIN "LIBVIRT_PRT"

typedef enum {
    IPTABLES_ACTION_INSERT,
    IPTABLES_ACTION_APPEND,
    IPTABLES_ACTION_DELETE,

    IPTABLES_ACTION_LAST
} iptablesAction;

VIR_ENUM_DECL(iptablesAction);
VIR_ENUM_IMPL(iptablesAction,
              IPTABLES_ACTION_LAST,
              "--insert",
              "--append",
              "--delete",
);

typedef struct {
    const char *parent;
    const char *child;
} iptablesGlobalChain;

typedef struct {
    virFirewallLayer layer;
    const char *table;
    iptablesGlobalChain *chains;
    size_t nchains;
    bool *changed;
} iptablesGlobalChainData;


static int
iptablesPrivateChainCreate(virFirewall *fw,
                           virFirewallLayer layer,
                           const char *const *lines,
                           void *opaque)
{
    iptablesGlobalChainData *data = opaque;
    g_autoptr(GHashTable) chains = virHashNew(NULL);
    g_autoptr(GHashTable) links = virHashNew(NULL);
    const char *const *tmp;
    size_t i;

    tmp = lines;
    while (tmp && *tmp) {
        if (STRPREFIX(*tmp, "-N ")) { /* eg "-N LIBVIRT_INP" */
            if (virHashUpdateEntry(chains, *tmp + 3, (void *)0x1) < 0)
                return -1;
        } else if (STRPREFIX(*tmp, "-A ")) { /* eg "-A INPUT -j LIBVIRT_INP" */
            char *sep = strchr(*tmp + 3, ' ');
            if (sep) {
                *sep = '\0';
                if (STRPREFIX(sep + 1, "-j ")) {
                    if (virHashUpdateEntry(links, sep + 4,
                                           (char *)*tmp + 3) < 0)
                        return -1;
                }
            }
        }
        tmp++;
    }

    for (i = 0; i < data->nchains; i++) {
        const char *from;
        if (!virHashLookup(chains, data->chains[i].child)) {
            virFirewallAddCmd(fw, layer,
                              "--table", data->table,
                              "--new-chain", data->chains[i].child, NULL);
            *data->changed = true;
        }

        from = virHashLookup(links, data->chains[i].child);
        if (!from || STRNEQ(from, data->chains[i].parent))
            virFirewallAddCmd(fw, layer,
                              "--table", data->table,
                              "--insert", data->chains[i].parent,
                              "--jump", data->chains[i].child, NULL);
    }

    return 0;
}


int
iptablesSetupPrivateChains(virFirewallLayer layer)
{
    g_autoptr(virFirewall) fw = virFirewallNew(VIR_FIREWALL_BACKEND_IPTABLES);
    iptablesGlobalChain filter_chains[] = {
        {"INPUT", VIR_IPTABLES_INPUT_CHAIN},
        {"OUTPUT", VIR_IPTABLES_OUTPUT_CHAIN},
        {"FORWARD", VIR_IPTABLES_FWD_OUT_CHAIN},
        {"FORWARD", VIR_IPTABLES_FWD_IN_CHAIN},
        {"FORWARD", VIR_IPTABLES_FWD_X_CHAIN},
    };
    iptablesGlobalChain natmangle_chains[] = {
        {"POSTROUTING",  VIR_IPTABLES_NAT_POSTROUTE_CHAIN},
    };
    bool changed = false;
    iptablesGlobalChainData data[] = {
        { layer, "filter",
          filter_chains, G_N_ELEMENTS(filter_chains), &changed },
        { layer, "nat",
          natmangle_chains, G_N_ELEMENTS(natmangle_chains), &changed },
        { layer, "mangle",
          natmangle_chains, G_N_ELEMENTS(natmangle_chains), &changed },
    };
    size_t i;

    /* When firewalld.service is active, we need to make sure that
     * firewalld has been fully started and completed its
     * initialization, otherwise it might delete our rules soon after
     * we add them!
     */
    virFirewallDSynchronize();

    virFirewallStartTransaction(fw, 0);

    for (i = 0; i < G_N_ELEMENTS(data); i++)
        virFirewallAddCmdFull(fw, data[i].layer,
                              false, iptablesPrivateChainCreate,
                              &(data[i]), "--table", data[i].table,
                              "--list-rules", NULL);

    if (virFirewallApply(fw) < 0)
        return -1;

    return changed ? 1 : 0;
}


static void
iptablesInput(virFirewall *fw,
              virFirewallLayer layer,
              const char *iface,
              int port,
              iptablesAction action,
              int tcp)
{
    g_autofree char *portstr = g_strdup_printf("%d", port);

    virFirewallAddCmd(fw, layer,
                      "--table", "filter",
                      iptablesActionTypeToString(action),
                      VIR_IPTABLES_INPUT_CHAIN,
                      "--in-interface", iface,
                      "--protocol", tcp ? "tcp" : "udp",
                      "--destination-port", portstr,
                      "--jump", "ACCEPT",
                      NULL);
}

static void
iptablesOutput(virFirewall *fw,
               virFirewallLayer layer,
               const char *iface,
               int port,
               iptablesAction action,
               int tcp)
{
    g_autofree char *portstr = g_strdup_printf("%d", port);

    virFirewallAddCmd(fw, layer,
                      "--table", "filter",
                      iptablesActionTypeToString(action),
                      VIR_IPTABLES_OUTPUT_CHAIN,
                      "--out-interface", iface,
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
 */
static void
iptablesAddTcpInput(virFirewall *fw,
                    virFirewallLayer layer,
                    const char *iface,
                    int port)
{
    iptablesInput(fw, layer, iface, port, IPTABLES_ACTION_INSERT, 1);
}

/**
 * iptablesRemoveTcpInput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the TCP port to remove
 *
 * Removes an input from the IP table, hence forbidding access to the given
 * @port on the given @iface interface for TCP packets
 */
static void
iptablesRemoveTcpInput(virFirewall *fw,
                       virFirewallLayer layer,
                       const char *iface,
                       int port)
{
    iptablesInput(fw, layer, iface, port, IPTABLES_ACTION_DELETE, 1);
}

/**
 * iptablesAddUdpInput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the UDP port to add
 *
 * Add an input to the IP table allowing access to the given @port on
 * the given @iface interface for UDP packets
 */
static void
iptablesAddUdpInput(virFirewall *fw,
                    virFirewallLayer layer,
                    const char *iface,
                    int port)
{
    iptablesInput(fw, layer, iface, port, IPTABLES_ACTION_INSERT, 0);
}

/**
 * iptablesRemoveUdpInput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the UDP port to remove
 *
 * Removes an input from the IP table, hence forbidding access to the given
 * @port on the given @iface interface for UDP packets
 */
static void
iptablesRemoveUdpInput(virFirewall *fw,
                       virFirewallLayer layer,
                       const char *iface,
                       int port)
{
    iptablesInput(fw, layer, iface, port, IPTABLES_ACTION_DELETE, 0);
}

/**
 * iptablesAddTcpOutput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the TCP port to add
 *
 * Add an output to the IP table allowing access to the given @port from
 * the given @iface interface for TCP packets
 */
static void
iptablesAddTcpOutput(virFirewall *fw,
                     virFirewallLayer layer,
                     const char *iface,
                     int port)
{
    iptablesOutput(fw, layer, iface, port, IPTABLES_ACTION_INSERT, 1);
}

/**
 * iptablesRemoveTcpOutput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the UDP port to remove
 *
 * Removes an output from the IP table, hence forbidding access to the given
 * @port from the given @iface interface for TCP packets
 */
static void
iptablesRemoveTcpOutput(virFirewall *fw,
                        virFirewallLayer layer,
                        const char *iface,
                        int port)
{
    iptablesOutput(fw, layer, iface, port, IPTABLES_ACTION_DELETE, 1);
}

/**
 * iptablesAddUdpOutput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the UDP port to add
 *
 * Add an output to the IP table allowing access to the given @port from
 * the given @iface interface for UDP packets
 */
static void
iptablesAddUdpOutput(virFirewall *fw,
                     virFirewallLayer layer,
                     const char *iface,
                     int port)
{
    iptablesOutput(fw, layer, iface, port, IPTABLES_ACTION_INSERT, 0);
}

/**
 * iptablesRemoveUdpOutput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the UDP port to remove
 *
 * Removes an output from the IP table, hence forbidding access to the given
 * @port from the given @iface interface for UDP packets
 */
static void
iptablesRemoveUdpOutput(virFirewall *fw,
                        virFirewallLayer layer,
                        const char *iface,
                        int port)
{
    iptablesOutput(fw, layer, iface, port, IPTABLES_ACTION_DELETE, 0);
}


/* Allow all traffic coming from the bridge, with a valid network address
 * to proceed to WAN
 */
static int
iptablesForwardAllowOut(virFirewall *fw,
                        virSocketAddr *netaddr,
                        unsigned int prefix,
                        const char *iface,
                        const char *physdev,
                        iptablesAction action)
{
    g_autofree char *networkstr = NULL;
    virFirewallLayer layer = VIR_SOCKET_ADDR_FAMILY(netaddr) == AF_INET ?
        VIR_FIREWALL_LAYER_IPV4 : VIR_FIREWALL_LAYER_IPV6;

    if (!(networkstr = virSocketAddrFormatWithPrefix(netaddr, prefix, true)))
        return -1;

    if (physdev && physdev[0])
        virFirewallAddCmd(fw, layer,
                          "--table", "filter",
                          iptablesActionTypeToString(action),
                          VIR_IPTABLES_FWD_OUT_CHAIN,
                          "--source", networkstr,
                          "--in-interface", iface,
                          "--out-interface", physdev,
                          "--jump", "ACCEPT",
                          NULL);
    else
        virFirewallAddCmd(fw, layer,
                          "--table", "filter",
                          iptablesActionTypeToString(action),
                          VIR_IPTABLES_FWD_OUT_CHAIN,
                          "--source", networkstr,
                          "--in-interface", iface,
                          "--jump", "ACCEPT",
                          NULL);

    return 0;
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
static int
iptablesAddForwardAllowOut(virFirewall *fw,
                           virSocketAddr *netaddr,
                           unsigned int prefix,
                           const char *iface,
                           const char *physdev)
{
    return iptablesForwardAllowOut(fw, netaddr, prefix, iface, physdev,
                                   IPTABLES_ACTION_INSERT);
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
static int
iptablesRemoveForwardAllowOut(virFirewall *fw,
                              virSocketAddr *netaddr,
                              unsigned int prefix,
                              const char *iface,
                              const char *physdev)
{
    return iptablesForwardAllowOut(fw, netaddr, prefix, iface, physdev,
                                   IPTABLES_ACTION_DELETE);
}


/* Allow all traffic destined to the bridge, with a valid network address
 * and associated with an existing connection
 */
static int
iptablesForwardAllowRelatedIn(virFirewall *fw,
                              virSocketAddr *netaddr,
                              unsigned int prefix,
                              const char *iface,
                              const char *physdev,
                              iptablesAction action)
{
    virFirewallLayer layer = VIR_SOCKET_ADDR_FAMILY(netaddr) == AF_INET ?
        VIR_FIREWALL_LAYER_IPV4 : VIR_FIREWALL_LAYER_IPV6;
    g_autofree char *networkstr = NULL;

    if (!(networkstr = virSocketAddrFormatWithPrefix(netaddr, prefix, true)))
        return -1;

    if (physdev && physdev[0])
        virFirewallAddCmd(fw, layer,
                          "--table", "filter",
                          iptablesActionTypeToString(action),
                          VIR_IPTABLES_FWD_IN_CHAIN,
                          "--destination", networkstr,
                          "--in-interface", physdev,
                          "--out-interface", iface,
                          "--match", "conntrack",
                          "--ctstate", "ESTABLISHED,RELATED",
                          "--jump", "ACCEPT",
                          NULL);
    else
        virFirewallAddCmd(fw, layer,
                          "--table", "filter",
                          iptablesActionTypeToString(action),
                          VIR_IPTABLES_FWD_IN_CHAIN,
                          "--destination", networkstr,
                          "--out-interface", iface,
                          "--match", "conntrack",
                          "--ctstate", "ESTABLISHED,RELATED",
                          "--jump", "ACCEPT",
                          NULL);

    return 0;
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
static int
iptablesAddForwardAllowRelatedIn(virFirewall *fw,
                                 virSocketAddr *netaddr,
                                 unsigned int prefix,
                                 const char *iface,
                                 const char *physdev)
{
    return iptablesForwardAllowRelatedIn(fw, netaddr, prefix, iface, physdev,
                                         IPTABLES_ACTION_INSERT);
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
static int
iptablesRemoveForwardAllowRelatedIn(virFirewall *fw,
                                    virSocketAddr *netaddr,
                                    unsigned int prefix,
                                    const char *iface,
                                    const char *physdev)
{
    return iptablesForwardAllowRelatedIn(fw, netaddr, prefix, iface, physdev,
                                         IPTABLES_ACTION_DELETE);
}

/* Allow all traffic destined to the bridge, with a valid network address
 */
static int
iptablesForwardAllowIn(virFirewall *fw,
                       virSocketAddr *netaddr,
                       unsigned int prefix,
                       const char *iface,
                       const char *physdev,
                       iptablesAction action)
{
    virFirewallLayer layer = VIR_SOCKET_ADDR_FAMILY(netaddr) == AF_INET ?
        VIR_FIREWALL_LAYER_IPV4 : VIR_FIREWALL_LAYER_IPV6;
    g_autofree char *networkstr = NULL;

    if (!(networkstr = virSocketAddrFormatWithPrefix(netaddr, prefix, true)))
        return -1;

    if (physdev && physdev[0])
        virFirewallAddCmd(fw, layer,
                          "--table", "filter",
                          iptablesActionTypeToString(action),
                          VIR_IPTABLES_FWD_IN_CHAIN,
                          "--destination", networkstr,
                          "--in-interface", physdev,
                          "--out-interface", iface,
                          "--jump", "ACCEPT",
                          NULL);
    else
        virFirewallAddCmd(fw, layer,
                          "--table", "filter",
                          iptablesActionTypeToString(action),
                          VIR_IPTABLES_FWD_IN_CHAIN,
                          "--destination", networkstr,
                          "--out-interface", iface,
                          "--jump", "ACCEPT",
                          NULL);
    return 0;
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
static int
iptablesAddForwardAllowIn(virFirewall *fw,
                          virSocketAddr *netaddr,
                          unsigned int prefix,
                          const char *iface,
                          const char *physdev)
{
    return iptablesForwardAllowIn(fw, netaddr, prefix, iface, physdev,
                                  IPTABLES_ACTION_INSERT);
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
static int
iptablesRemoveForwardAllowIn(virFirewall *fw,
                             virSocketAddr *netaddr,
                             unsigned int prefix,
                             const char *iface,
                             const char *physdev)
{
    return iptablesForwardAllowIn(fw, netaddr, prefix, iface, physdev,
                                  IPTABLES_ACTION_DELETE);
}

static void
iptablesForwardAllowCross(virFirewall *fw,
                          virFirewallLayer layer,
                          const char *iface,
                          iptablesAction action)
{
    virFirewallAddCmd(fw, layer,
                      "--table", "filter",
                      iptablesActionTypeToString(action),
                      VIR_IPTABLES_FWD_X_CHAIN,
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
static void
iptablesAddForwardAllowCross(virFirewall *fw,
                             virFirewallLayer layer,
                             const char *iface)
{
    iptablesForwardAllowCross(fw, layer, iface, IPTABLES_ACTION_INSERT);
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
static void
iptablesRemoveForwardAllowCross(virFirewall *fw,
                                virFirewallLayer layer,
                                const char *iface)
{
    iptablesForwardAllowCross(fw, layer, iface, IPTABLES_ACTION_DELETE);
}

static void
iptablesForwardRejectOut(virFirewall *fw,
                         virFirewallLayer layer,
                         const char *iface,
                         iptablesAction action)
{
    virFirewallAddCmd(fw, layer,
                      "--table", "filter",
                      iptablesActionTypeToString(action),
                      VIR_IPTABLES_FWD_OUT_CHAIN,
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
static void
iptablesAddForwardRejectOut(virFirewall *fw,
                            virFirewallLayer layer,
                            const char *iface)
{
    iptablesForwardRejectOut(fw, layer, iface, IPTABLES_ACTION_INSERT);
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
static void
iptablesRemoveForwardRejectOut(virFirewall *fw,
                               virFirewallLayer layer,
                               const char *iface)
{
    iptablesForwardRejectOut(fw, layer, iface, IPTABLES_ACTION_DELETE);
}


static void
iptablesForwardRejectIn(virFirewall *fw,
                        virFirewallLayer layer,
                        const char *iface,
                        iptablesAction action)
{
    virFirewallAddCmd(fw, layer,
                      "--table", "filter",
                      iptablesActionTypeToString(action),
                      VIR_IPTABLES_FWD_IN_CHAIN,
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
static void
iptablesAddForwardRejectIn(virFirewall *fw,
                           virFirewallLayer layer,
                           const char *iface)
{
    iptablesForwardRejectIn(fw, layer, iface, IPTABLES_ACTION_INSERT);
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
static void
iptablesRemoveForwardRejectIn(virFirewall *fw,
                              virFirewallLayer layer,
                              const char *iface)
{
    iptablesForwardRejectIn(fw, layer, iface, IPTABLES_ACTION_DELETE);
}


/* Masquerade all traffic coming from the network associated
 * with the bridge
 */
static int
iptablesForwardMasquerade(virFirewall *fw,
                          virSocketAddr *netaddr,
                          unsigned int prefix,
                          const char *physdev,
                          virSocketAddrRange *addr,
                          virPortRange *port,
                          const char *protocol,
                          iptablesAction action)
{
    g_autofree char *networkstr = NULL;
    g_autofree char *addrStartStr = NULL;
    g_autofree char *addrEndStr = NULL;
    g_autofree char *portRangeStr = NULL;
    g_autofree char *natRangeStr = NULL;
    virFirewallCmd *fwCmd;
    int af = VIR_SOCKET_ADDR_FAMILY(netaddr);
    virFirewallLayer layer = af == AF_INET ?
        VIR_FIREWALL_LAYER_IPV4 : VIR_FIREWALL_LAYER_IPV6;

    if (!(networkstr = virSocketAddrFormatWithPrefix(netaddr, prefix, true)))
        return -1;

    if (VIR_SOCKET_ADDR_IS_FAMILY(&addr->start, af)) {
        if (!(addrStartStr = virSocketAddrFormat(&addr->start)))
            return -1;
        if (VIR_SOCKET_ADDR_IS_FAMILY(&addr->end, af)) {
            if (!(addrEndStr = virSocketAddrFormat(&addr->end)))
                return -1;
        }
    }

    if (protocol && protocol[0]) {
        fwCmd = virFirewallAddCmd(fw, layer,
                                  "--table", "nat",
                                  iptablesActionTypeToString(action),
                                  VIR_IPTABLES_NAT_POSTROUTE_CHAIN,
                                  "--source", networkstr,
                                  "-p", protocol,
                                  "!", "--destination", networkstr,
                                  NULL);
    } else {
        fwCmd = virFirewallAddCmd(fw, layer,
                                  "--table", "nat",
                                  iptablesActionTypeToString(action),
                                  VIR_IPTABLES_NAT_POSTROUTE_CHAIN,
                                  "--source", networkstr,
                                  "!", "--destination", networkstr,
                                  NULL);
    }

    if (physdev && physdev[0])
        virFirewallCmdAddArgList(fw, fwCmd, "--out-interface", physdev, NULL);

    if (protocol && protocol[0]) {
        if (port->start == 0 && port->end == 0) {
            port->start = 1024;
            port->end = 65535;
        }

        if (port->start < port->end && port->end < 65536) {
            portRangeStr = g_strdup_printf(":%u-%u", port->start, port->end);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid port range '%1$u-%2$u'."),
                           port->start, port->end);
            return -1;
        }
    }

    /* Use --jump SNAT if public addr is specified */
    if (addrStartStr && addrStartStr[0]) {
        if (addrEndStr && addrEndStr[0]) {
            natRangeStr = g_strdup_printf("%s-%s%s", addrStartStr, addrEndStr,
                                          portRangeStr ? portRangeStr : "");
        } else {
            natRangeStr = g_strdup_printf("%s%s", addrStartStr,
                                          portRangeStr ? portRangeStr : "");
        }

        virFirewallCmdAddArgList(fw, fwCmd,
                                 "--jump", "SNAT",
                                 "--to-source", natRangeStr, NULL);
    } else {
        virFirewallCmdAddArgList(fw, fwCmd,
                                 "--jump", "MASQUERADE", NULL);

        if (portRangeStr && portRangeStr[0])
            virFirewallCmdAddArgList(fw, fwCmd,
                                     "--to-ports", &portRangeStr[1], NULL);
    }

    return 0;
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
static int
iptablesAddForwardMasquerade(virFirewall *fw,
                             virSocketAddr *netaddr,
                             unsigned int prefix,
                             const char *physdev,
                             virSocketAddrRange *addr,
                             virPortRange *port,
                             const char *protocol)
{
    return iptablesForwardMasquerade(fw, netaddr, prefix,
                                     physdev, addr, port, protocol,
                                     IPTABLES_ACTION_INSERT);
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
static int
iptablesRemoveForwardMasquerade(virFirewall *fw,
                                virSocketAddr *netaddr,
                                unsigned int prefix,
                                const char *physdev,
                                virSocketAddrRange *addr,
                                virPortRange *port,
                                const char *protocol)
{
    return iptablesForwardMasquerade(fw, netaddr, prefix,
                                     physdev, addr, port, protocol,
                                     IPTABLES_ACTION_DELETE);
}


/* Don't masquerade traffic coming from the network associated with the bridge
 * if said traffic targets @destaddr.
 */
static int
iptablesForwardDontMasquerade(virFirewall *fw,
                              virSocketAddr *netaddr,
                              unsigned int prefix,
                              const char *physdev,
                              const char *destaddr,
                              iptablesAction action)
{
    g_autofree char *networkstr = NULL;
    virFirewallLayer layer = VIR_SOCKET_ADDR_FAMILY(netaddr) == AF_INET ?
        VIR_FIREWALL_LAYER_IPV4 : VIR_FIREWALL_LAYER_IPV6;

    if (!(networkstr = virSocketAddrFormatWithPrefix(netaddr, prefix, true)))
        return -1;

    if (physdev && physdev[0])
        virFirewallAddCmd(fw, layer,
                          "--table", "nat",
                          iptablesActionTypeToString(action),
                          VIR_IPTABLES_NAT_POSTROUTE_CHAIN,
                          "--out-interface", physdev,
                          "--source", networkstr,
                          "--destination", destaddr,
                          "--jump", "RETURN",
                          NULL);
    else
        virFirewallAddCmd(fw, layer,
                          "--table", "nat",
                          iptablesActionTypeToString(action),
                          VIR_IPTABLES_NAT_POSTROUTE_CHAIN,
                          "--source", networkstr,
                          "--destination", destaddr,
                          "--jump", "RETURN",
                          NULL);

    return 0;
}

/**
 * iptablesAddDontMasquerade:
 * @netaddr: the source network name
 * @prefix: prefix (# of 1 bits) of netmask to apply to @netaddr
 * @physdev: the physical output device or NULL
 * @destaddr: the destination network not to masquerade for
 *
 * Add rules to the IP table context to avoid masquerading from
 * @netaddr/@prefix to @destaddr on @physdev. @destaddr must be in a format
 * directly consumable by iptables, it must not depend on user input or
 * configuration.
 *
 * Returns 0 in case of success or an error code otherwise.
 */
static int
iptablesAddDontMasquerade(virFirewall *fw,
                          virSocketAddr *netaddr,
                          unsigned int prefix,
                          const char *physdev,
                          const char *destaddr)
{
    return iptablesForwardDontMasquerade(fw, netaddr, prefix,
                                         physdev, destaddr, IPTABLES_ACTION_INSERT);
}

/**
 * iptablesRemoveDontMasquerade:
 * @netaddr: the source network name
 * @prefix: prefix (# of 1 bits) of netmask to apply to @netaddr
 * @physdev: the physical output device or NULL
 * @destaddr: the destination network not to masquerade for
 *
 * Remove rules from the IP table context that prevent masquerading from
 * @netaddr/@prefix to @destaddr on @physdev. @destaddr must be in a format
 * directly consumable by iptables, it must not depend on user input or
 * configuration.
 *
 * Returns 0 in case of success or an error code otherwise.
 */
static int
iptablesRemoveDontMasquerade(virFirewall *fw,
                             virSocketAddr *netaddr,
                             unsigned int prefix,
                             const char *physdev,
                             const char *destaddr)
{
    return iptablesForwardDontMasquerade(fw, netaddr, prefix,
                                         physdev, destaddr,
                                         IPTABLES_ACTION_DELETE);
}


static void
iptablesOutputFixUdpChecksum(virFirewall *fw,
                             const char *iface,
                             int port,
                             iptablesAction action)
{
    g_autofree char *portstr = g_strdup_printf("%d", port);

    virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_IPV4,
                      "--table", "mangle",
                      iptablesActionTypeToString(action),
                      VIR_IPTABLES_NAT_POSTROUTE_CHAIN,
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
 */
static void
iptablesAddOutputFixUdpChecksum(virFirewall *fw,
                                const char *iface,
                                int port)
{
    iptablesOutputFixUdpChecksum(fw, iface, port, IPTABLES_ACTION_INSERT);
}

/**
 * iptablesRemoveOutputFixUdpChecksum:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the UDP port of the rule to remove
 *
 * Removes the checksum fixup rule that was previous added with
 * iptablesAddOutputFixUdpChecksum.
 */
static void
iptablesRemoveOutputFixUdpChecksum(virFirewall *fw,
                                   const char *iface,
                                   int port)
{
    iptablesOutputFixUdpChecksum(fw, iface, port, IPTABLES_ACTION_DELETE);
}


static const char networkLocalMulticastIPv4[] = "224.0.0.0/24";
static const char networkLocalMulticastIPv6[] = "ff02::/16";
static const char networkLocalBroadcast[] = "255.255.255.255/32";

static int
iptablesAddMasqueradingFirewallRules(virFirewall *fw,
                                    virNetworkDef *def,
                                    virNetworkIPDef *ipdef)
{
    int prefix = virNetworkIPDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(def, 0);
    bool isIPv4 = VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET);

    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid prefix or netmask for '%1$s'"),
                       def->bridge);
        return -1;
    }

    /* allow forwarding packets from the bridge interface */
    if (iptablesAddForwardAllowOut(fw,
                                   &ipdef->address,
                                   prefix,
                                   def->bridge,
                                   forwardIf) < 0)
        return -1;

    /* allow forwarding packets to the bridge interface if they are
     * part of an existing connection
     */
    if (iptablesAddForwardAllowRelatedIn(fw,
                                         &ipdef->address,
                                         prefix,
                                         def->bridge,
                                         forwardIf) < 0)
        return -1;

    /*
     * Enable masquerading.
     *
     * We need to end up with 5 rules in the table in this order
     *
     *  1. do not masquerade packets targeting 224.0.0.0/24
     *  2. do not masquerade packets targeting 255.255.255.255/32
     *  3. masquerade protocol=tcp with sport mapping restriction
     *  4. masquerade protocol=udp with sport mapping restriction
     *  5. generic, masquerade any protocol
     *
     * 224.0.0.0/24 is the local network multicast range. Packets are not
     * forwarded outside.
     *
     * 255.255.255.255/32 is the broadcast address of any local network. Again,
     * such packets are never forwarded, but strict DHCP clients don't accept
     * DHCP replies with changed source ports.
     *
     * The sport mappings are required, because default IPtables
     * MASQUERADE maintain port numbers unchanged where possible.
     *
     * NFS can be configured to only "trust" port numbers < 1023.
     *
     * Guests using NAT thus need to be prevented from having port
     * numbers < 1023, otherwise they can bypass the NFS "security"
     * check on the source port number.
     *
     * Since we use '--insert' to add rules to the header of the
     * chain, we actually need to add them in the reverse of the
     * order just mentioned !
     */

    /* First the generic masquerade rule for other protocols */
    if (iptablesAddForwardMasquerade(fw,
                                     &ipdef->address,
                                     prefix,
                                     forwardIf,
                                     &def->forward.addr,
                                     &def->forward.port,
                                     NULL) < 0)
        return -1;

    /* UDP with a source port restriction */
    if (iptablesAddForwardMasquerade(fw,
                                     &ipdef->address,
                                     prefix,
                                     forwardIf,
                                     &def->forward.addr,
                                     &def->forward.port,
                                     "udp") < 0)
        return -1;

    /* TCP with a source port restriction */
    if (iptablesAddForwardMasquerade(fw,
                                     &ipdef->address,
                                     prefix,
                                     forwardIf,
                                     &def->forward.addr,
                                     &def->forward.port,
                                     "tcp") < 0)
        return -1;

    /* exempt local network broadcast address as destination */
    if (isIPv4 &&
        iptablesAddDontMasquerade(fw,
                                  &ipdef->address,
                                  prefix,
                                  forwardIf,
                                  networkLocalBroadcast) < 0)
        return -1;

    /* exempt local multicast range as destination */
    if (iptablesAddDontMasquerade(fw,
                                  &ipdef->address,
                                  prefix,
                                  forwardIf,
                                  isIPv4 ? networkLocalMulticastIPv4 :
                                  networkLocalMulticastIPv6) < 0)
        return -1;

    return 0;
}

static int
iptablesRemoveMasqueradingFirewallRules(virFirewall *fw,
                                       virNetworkDef *def,
                                       virNetworkIPDef *ipdef)
{
    int prefix = virNetworkIPDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(def, 0);
    bool isIPv4 = VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET);

    if (prefix < 0)
        return 0;

    if (iptablesRemoveDontMasquerade(fw,
                                     &ipdef->address,
                                     prefix,
                                     forwardIf,
                                     isIPv4 ? networkLocalMulticastIPv4 :
                                     networkLocalMulticastIPv6) < 0)
        return -1;

    if (isIPv4 &&
        iptablesRemoveDontMasquerade(fw,
                                     &ipdef->address,
                                     prefix,
                                     forwardIf,
                                     networkLocalBroadcast) < 0)
        return -1;

    if (iptablesRemoveForwardMasquerade(fw,
                                        &ipdef->address,
                                        prefix,
                                        forwardIf,
                                        &def->forward.addr,
                                        &def->forward.port,
                                        "tcp") < 0)
        return -1;

    if (iptablesRemoveForwardMasquerade(fw,
                                        &ipdef->address,
                                        prefix,
                                        forwardIf,
                                        &def->forward.addr,
                                        &def->forward.port,
                                        "udp") < 0)
        return -1;

    if (iptablesRemoveForwardMasquerade(fw,
                                        &ipdef->address,
                                        prefix,
                                        forwardIf,
                                        &def->forward.addr,
                                        &def->forward.port,
                                        NULL) < 0)
        return -1;

    if (iptablesRemoveForwardAllowRelatedIn(fw,
                                            &ipdef->address,
                                            prefix,
                                            def->bridge,
                                            forwardIf) < 0)
        return -1;

    if (iptablesRemoveForwardAllowOut(fw,
                                      &ipdef->address,
                                      prefix,
                                      def->bridge,
                                      forwardIf) < 0)
        return -1;

    return 0;
}


static int
iptablesAddRoutingFirewallRules(virFirewall *fw,
                               virNetworkDef *def,
                               virNetworkIPDef *ipdef)
{
    int prefix = virNetworkIPDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(def, 0);

    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid prefix or netmask for '%1$s'"),
                       def->bridge);
        return -1;
    }

    /* allow routing packets from the bridge interface */
    if (iptablesAddForwardAllowOut(fw,
                                   &ipdef->address,
                                   prefix,
                                   def->bridge,
                                   forwardIf) < 0)
        return -1;

    /* allow routing packets to the bridge interface */
    if (iptablesAddForwardAllowIn(fw,
                                  &ipdef->address,
                                  prefix,
                                  def->bridge,
                                  forwardIf) < 0)
        return -1;

    return 0;
}


static int
iptablesRemoveRoutingFirewallRules(virFirewall *fw,
                                  virNetworkDef *def,
                                  virNetworkIPDef *ipdef)
{
    int prefix = virNetworkIPDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(def, 0);

    if (prefix < 0)
        return 0;

    if (iptablesRemoveForwardAllowIn(fw,
                                     &ipdef->address,
                                     prefix,
                                     def->bridge,
                                     forwardIf) < 0)
        return -1;

    if (iptablesRemoveForwardAllowOut(fw,
                                      &ipdef->address,
                                      prefix,
                                      def->bridge,
                                      forwardIf) < 0)
        return -1;

    return 0;
}


static void
iptablesAddGeneralIPv4FirewallRules(virFirewall *fw,
                                   virNetworkDef *def)
{
    size_t i;
    virNetworkIPDef *ipv4def;

    /* First look for first IPv4 address that has dhcp or tftpboot defined. */
    /* We support dhcp config on 1 IPv4 interface only. */
    for (i = 0;
         (ipv4def = virNetworkDefGetIPByIndex(def, AF_INET, i));
         i++) {
        if (ipv4def->nranges || ipv4def->nhosts || ipv4def->tftproot)
            break;
    }

    /* allow DHCP requests through to dnsmasq & back out */
    iptablesAddTcpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 67);
    iptablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 67);
    iptablesAddTcpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 68);
    iptablesAddUdpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 68);

    /* allow DNS requests through to dnsmasq & back out */
    iptablesAddTcpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);
    iptablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);
    iptablesAddTcpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);
    iptablesAddUdpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);

    /* allow TFTP requests through to dnsmasq if necessary & back out */
    if (ipv4def && ipv4def->tftproot) {
        iptablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 69);
        iptablesAddUdpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 69);
    }

    /* Catch all rules to block forwarding to/from bridges */
    iptablesAddForwardRejectOut(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);
    iptablesAddForwardRejectIn(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);

    /* Allow traffic between guests on the same bridge */
    iptablesAddForwardAllowCross(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);
}

static void
iptablesRemoveGeneralIPv4FirewallRules(virFirewall *fw,
                                      virNetworkDef *def)
{
    size_t i;
    virNetworkIPDef *ipv4def;

    for (i = 0;
         (ipv4def = virNetworkDefGetIPByIndex(def, AF_INET, i));
         i++) {
        if (ipv4def->nranges || ipv4def->nhosts || ipv4def->tftproot)
            break;
    }

    iptablesRemoveForwardAllowCross(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);
    iptablesRemoveForwardRejectIn(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);
    iptablesRemoveForwardRejectOut(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);

    if (ipv4def && ipv4def->tftproot) {
        iptablesRemoveUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 69);
        iptablesRemoveUdpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 69);
    }

    iptablesRemoveUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);
    iptablesRemoveTcpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);
    iptablesRemoveUdpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);
    iptablesRemoveTcpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);

    iptablesRemoveUdpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 68);
    iptablesRemoveTcpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 68);
    iptablesRemoveUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 67);
    iptablesRemoveTcpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 67);
}


/* Add all once/network rules required for IPv6.
 * If no IPv6 addresses are defined and <network ipv6='yes'> is
 * specified, then allow IPv6 communications between virtual systems.
 * If any IPv6 addresses are defined, then add the rules for regular operation.
 */
static void
iptablesAddGeneralIPv6FirewallRules(virFirewall *fw,
                                   virNetworkDef *def)
{
    if (!virNetworkDefGetIPByIndex(def, AF_INET6, 0) &&
        !def->ipv6nogw) {
        return;
    }

    /* Catch all rules to block forwarding to/from bridges */
    iptablesAddForwardRejectOut(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge);
    iptablesAddForwardRejectIn(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge);

    /* Allow traffic between guests on the same bridge */
    iptablesAddForwardAllowCross(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge);

    if (virNetworkDefGetIPByIndex(def, AF_INET6, 0)) {
        /* allow DNS over IPv6 & back out */
        iptablesAddTcpInput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
        iptablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
        iptablesAddTcpOutput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
        iptablesAddUdpOutput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
        /* allow DHCPv6 & back out */
        iptablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 547);
        iptablesAddUdpOutput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 546);
    }
}

static void
iptablesRemoveGeneralIPv6FirewallRules(virFirewall *fw,
                                      virNetworkDef *def)
{
    if (!virNetworkDefGetIPByIndex(def, AF_INET6, 0) &&
        !def->ipv6nogw) {
        return;
    }

    if (virNetworkDefGetIPByIndex(def, AF_INET6, 0)) {
        iptablesRemoveUdpOutput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 546);
        iptablesRemoveUdpInput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 547);
        iptablesRemoveUdpOutput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
        iptablesRemoveTcpOutput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
        iptablesRemoveUdpInput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
        iptablesRemoveTcpInput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
    }

    /* the following rules are there if no IPv6 address has been defined
     * but def->ipv6nogw == true
     */
    iptablesRemoveForwardAllowCross(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge);
    iptablesRemoveForwardRejectIn(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge);
    iptablesRemoveForwardRejectOut(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge);
}


static void
iptablesAddGeneralFirewallRules(virFirewall *fw,
                               virNetworkDef *def)
{
    iptablesAddGeneralIPv4FirewallRules(fw, def);
    iptablesAddGeneralIPv6FirewallRules(fw, def);
}


static void
iptablesRemoveGeneralFirewallRules(virFirewall *fw,
                                  virNetworkDef *def)
{
    iptablesRemoveGeneralIPv4FirewallRules(fw, def);
    iptablesRemoveGeneralIPv6FirewallRules(fw, def);
}

static void
iptablesAddChecksumFirewallRules(virFirewall *fw,
                                virNetworkDef *def)
{
    size_t i;
    virNetworkIPDef *ipv4def;

    /* First look for first IPv4 address that has dhcp or tftpboot defined. */
    /* We support dhcp config on 1 IPv4 interface only. */
    for (i = 0;
         (ipv4def = virNetworkDefGetIPByIndex(def, AF_INET, i));
         i++) {
        if (ipv4def->nranges || ipv4def->nhosts)
            break;
    }

    /* If we are doing local DHCP service on this network, attempt to
     * add a rule that will fixup the checksum of DHCP response
     * packets back to the guests (but report failure without
     * aborting, since not all iptables implementations support it).
     */
    if (ipv4def)
        iptablesAddOutputFixUdpChecksum(fw, def->bridge, 68);
}


static void
iptablesRemoveChecksumFirewallRules(virFirewall *fw,
                                   virNetworkDef *def)
{
    size_t i;
    virNetworkIPDef *ipv4def;

    /* First look for first IPv4 address that has dhcp or tftpboot defined. */
    /* We support dhcp config on 1 IPv4 interface only. */
    for (i = 0;
         (ipv4def = virNetworkDefGetIPByIndex(def, AF_INET, i));
         i++) {
        if (ipv4def->nranges || ipv4def->nhosts)
            break;
    }

    if (ipv4def)
        iptablesRemoveOutputFixUdpChecksum(fw, def->bridge, 68);
}


static int
iptablesAddIPSpecificFirewallRules(virFirewall *fw,
                                  virNetworkDef *def,
                                  virNetworkIPDef *ipdef)
{
    /* NB: in the case of IPv6, routing rules are added when the
     * forward mode is NAT. This is because IPv6 has no NAT.
     */

    if (def->forward.type == VIR_NETWORK_FORWARD_NAT) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET) ||
            def->forward.natIPv6 == VIR_TRISTATE_BOOL_YES)
            return iptablesAddMasqueradingFirewallRules(fw, def, ipdef);
        else if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            return iptablesAddRoutingFirewallRules(fw, def, ipdef);
    } else if (def->forward.type == VIR_NETWORK_FORWARD_ROUTE) {
        return iptablesAddRoutingFirewallRules(fw, def, ipdef);
    }
    return 0;
}


static int
iptablesRemoveIPSpecificFirewallRules(virFirewall *fw,
                                     virNetworkDef *def,
                                     virNetworkIPDef *ipdef)
{
    if (def->forward.type == VIR_NETWORK_FORWARD_NAT) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET) ||
            def->forward.natIPv6 == VIR_TRISTATE_BOOL_YES)
            return iptablesRemoveMasqueradingFirewallRules(fw, def, ipdef);
        else if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            return iptablesRemoveRoutingFirewallRules(fw, def, ipdef);
    } else if (def->forward.type == VIR_NETWORK_FORWARD_ROUTE) {
        return iptablesRemoveRoutingFirewallRules(fw, def, ipdef);
    }
    return 0;
}


/* iptablesAddFirewallrules:
 *
 * @def - the network that needs an iptables firewall added
 * @fwRemoval - if this is not NULL, it points to a pointer
 *    that should be filled in with a virFirewall object containing
 *    all the commands needed to remove this firewall at a later time.
 *
 * Add all rules for all ip addresses (and general rules) on a
 * network, and optionally return a virFirewall object containing all
 * the rules needed to later remove the firewall that has been added.
*/
int
iptablesAddFirewallRules(virNetworkDef *def, virFirewall **fwRemoval)
{
    size_t i;
    virNetworkIPDef *ipdef;
    g_autoptr(virFirewall) fw = virFirewallNew(VIR_FIREWALL_BACKEND_IPTABLES);

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_AUTO_ROLLBACK);

    iptablesAddGeneralFirewallRules(fw, def);

    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i));
         i++) {
        if (iptablesAddIPSpecificFirewallRules(fw, def, ipdef) < 0)
            return -1;
    }

    virFirewallStartTransaction(fw, (VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS |
                                     VIR_FIREWALL_TRANSACTION_AUTO_ROLLBACK));
    iptablesAddChecksumFirewallRules(fw, def);

    if (virFirewallApply(fw) < 0)
        return -1;

    if (fwRemoval) {
        /* caller wants us to create a virFirewall object that can be
         * applied to undo everything that was just done by * virFirewallApply()
         */

        if (virFirewallNewFromRollback(fw, fwRemoval) < 0)
            return -1;
    }

    return 0;
}

/* iptablesRemoveFirewallRules:
 *
 * @def - the network that needs its iptables firewall rules removed
 *
 * Remove all rules for all ip addresses (and general rules) on a
 * network that is being shut down.
 *
 * This function assumes the set of iptables rules that were added by
 * all versions of libvirt prior to 10.4.0; any libvirt of that
 * release or newer may or may not have this same set of rules, and
 * should be using the list of commands saved in NetworkObj::fwRemoval
 * (<fwRemoval> element in the network status XML) to remove the
 * network's firewall rules.
 */
void
iptablesRemoveFirewallRules(virNetworkDef *def)
{
    size_t i;
    virNetworkIPDef *ipdef;
    g_autoptr(virFirewall) fw = virFirewallNew(VIR_FIREWALL_BACKEND_IPTABLES);

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);
    iptablesRemoveChecksumFirewallRules(fw, def);

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);

    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i));
         i++) {
        if (iptablesRemoveIPSpecificFirewallRules(fw, def, ipdef) < 0)
            return;
    }
    iptablesRemoveGeneralFirewallRules(fw, def);

    virFirewallApply(fw);
}
