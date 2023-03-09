/*
 * viriptables.c: helper APIs for managing iptables
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
#include "viriptables.h"
#include "virfirewalld.h"
#include "virerror.h"
#include "virlog.h"
#include "virhash.h"

VIR_LOG_INIT("util.iptables");

#define VIR_FROM_THIS VIR_FROM_NONE

enum {
    VIR_NETFILTER_INSERT = 0,
    VIR_NETFILTER_DELETE
};

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
            virFirewallAddRule(fw, layer,
                               "--table", data->table,
                               "--new-chain", data->chains[i].child, NULL);
            *data->changed = true;
        }

        from = virHashLookup(links, data->chains[i].child);
        if (!from || STRNEQ(from, data->chains[i].parent))
            virFirewallAddRule(fw, layer,
                               "--table", data->table,
                               "--insert", data->chains[i].parent,
                               "--jump", data->chains[i].child, NULL);
    }

    return 0;
}


int
iptablesSetupPrivateChains(virFirewallLayer layer)
{
    g_autoptr(virFirewall) fw = virFirewallNew();
    iptablesGlobalChain filter_chains[] = {
        {"INPUT", "LIBVIRT_INP"},
        {"OUTPUT", "LIBVIRT_OUT"},
        {"FORWARD", "LIBVIRT_FWO"},
        {"FORWARD", "LIBVIRT_FWI"},
        {"FORWARD", "LIBVIRT_FWX"},
    };
    iptablesGlobalChain natmangle_chains[] = {
        {"POSTROUTING",  "LIBVIRT_PRT"},
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
        virFirewallAddRuleFull(fw, data[i].layer,
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
              int action,
              int tcp)
{
    g_autofree char *portstr = g_strdup_printf("%d", port);

    virFirewallAddRule(fw, layer,
                       "--table", "filter",
                       action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                       "LIBVIRT_INP",
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
               int action,
               int tcp)
{
    g_autofree char *portstr = g_strdup_printf("%d", port);

    virFirewallAddRule(fw, layer,
                       "--table", "filter",
                       action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                       "LIBVIRT_OUT",
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
void
iptablesAddTcpInput(virFirewall *fw,
                    virFirewallLayer layer,
                    const char *iface,
                    int port)
{
    iptablesInput(fw, layer, iface, port, VIR_NETFILTER_INSERT, 1);
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
void
iptablesRemoveTcpInput(virFirewall *fw,
                       virFirewallLayer layer,
                       const char *iface,
                       int port)
{
    iptablesInput(fw, layer, iface, port, VIR_NETFILTER_DELETE, 1);
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
void
iptablesAddUdpInput(virFirewall *fw,
                    virFirewallLayer layer,
                    const char *iface,
                    int port)
{
    iptablesInput(fw, layer, iface, port, VIR_NETFILTER_INSERT, 0);
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
void
iptablesRemoveUdpInput(virFirewall *fw,
                       virFirewallLayer layer,
                       const char *iface,
                       int port)
{
    iptablesInput(fw, layer, iface, port, VIR_NETFILTER_DELETE, 0);
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
void
iptablesAddTcpOutput(virFirewall *fw,
                     virFirewallLayer layer,
                     const char *iface,
                     int port)
{
    iptablesOutput(fw, layer, iface, port, VIR_NETFILTER_INSERT, 1);
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
void
iptablesRemoveTcpOutput(virFirewall *fw,
                        virFirewallLayer layer,
                        const char *iface,
                        int port)
{
    iptablesOutput(fw, layer, iface, port, VIR_NETFILTER_DELETE, 1);
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
void
iptablesAddUdpOutput(virFirewall *fw,
                     virFirewallLayer layer,
                     const char *iface,
                     int port)
{
    iptablesOutput(fw, layer, iface, port, VIR_NETFILTER_INSERT, 0);
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
void
iptablesRemoveUdpOutput(virFirewall *fw,
                        virFirewallLayer layer,
                        const char *iface,
                        int port)
{
    iptablesOutput(fw, layer, iface, port, VIR_NETFILTER_DELETE, 0);
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
                        int action)
{
    g_autofree char *networkstr = NULL;
    virFirewallLayer layer = VIR_SOCKET_ADDR_FAMILY(netaddr) == AF_INET ?
        VIR_FIREWALL_LAYER_IPV4 : VIR_FIREWALL_LAYER_IPV6;

    if (!(networkstr = virSocketAddrFormatWithPrefix(netaddr, prefix, true)))
        return -1;

    if (physdev && physdev[0])
        virFirewallAddRule(fw, layer,
                           "--table", "filter",
                           action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                           "LIBVIRT_FWO",
                           "--source", networkstr,
                           "--in-interface", iface,
                           "--out-interface", physdev,
                           "--jump", "ACCEPT",
                           NULL);
    else
        virFirewallAddRule(fw, layer,
                           "--table", "filter",
                           action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                           "LIBVIRT_FWO",
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
int
iptablesAddForwardAllowOut(virFirewall *fw,
                           virSocketAddr *netaddr,
                           unsigned int prefix,
                           const char *iface,
                           const char *physdev)
{
    return iptablesForwardAllowOut(fw, netaddr, prefix, iface, physdev,
                                   VIR_NETFILTER_INSERT);
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
iptablesRemoveForwardAllowOut(virFirewall *fw,
                              virSocketAddr *netaddr,
                              unsigned int prefix,
                              const char *iface,
                              const char *physdev)
{
    return iptablesForwardAllowOut(fw, netaddr, prefix, iface, physdev,
                                   VIR_NETFILTER_DELETE);
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
                              int action)
{
    virFirewallLayer layer = VIR_SOCKET_ADDR_FAMILY(netaddr) == AF_INET ?
        VIR_FIREWALL_LAYER_IPV4 : VIR_FIREWALL_LAYER_IPV6;
    g_autofree char *networkstr = NULL;

    if (!(networkstr = virSocketAddrFormatWithPrefix(netaddr, prefix, true)))
        return -1;

    if (physdev && physdev[0])
        virFirewallAddRule(fw, layer,
                           "--table", "filter",
                           action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                           "LIBVIRT_FWI",
                           "--destination", networkstr,
                           "--in-interface", physdev,
                           "--out-interface", iface,
                           "--match", "conntrack",
                           "--ctstate", "ESTABLISHED,RELATED",
                           "--jump", "ACCEPT",
                           NULL);
    else
        virFirewallAddRule(fw, layer,
                           "--table", "filter",
                           action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                           "LIBVIRT_FWI",
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
int
iptablesAddForwardAllowRelatedIn(virFirewall *fw,
                                 virSocketAddr *netaddr,
                                 unsigned int prefix,
                                 const char *iface,
                                 const char *physdev)
{
    return iptablesForwardAllowRelatedIn(fw, netaddr, prefix, iface, physdev,
                                         VIR_NETFILTER_INSERT);
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
iptablesRemoveForwardAllowRelatedIn(virFirewall *fw,
                                    virSocketAddr *netaddr,
                                    unsigned int prefix,
                                    const char *iface,
                                    const char *physdev)
{
    return iptablesForwardAllowRelatedIn(fw, netaddr, prefix, iface, physdev,
                                         VIR_NETFILTER_DELETE);
}

/* Allow all traffic destined to the bridge, with a valid network address
 */
static int
iptablesForwardAllowIn(virFirewall *fw,
                       virSocketAddr *netaddr,
                       unsigned int prefix,
                       const char *iface,
                       const char *physdev,
                       int action)
{
    virFirewallLayer layer = VIR_SOCKET_ADDR_FAMILY(netaddr) == AF_INET ?
        VIR_FIREWALL_LAYER_IPV4 : VIR_FIREWALL_LAYER_IPV6;
    g_autofree char *networkstr = NULL;

    if (!(networkstr = virSocketAddrFormatWithPrefix(netaddr, prefix, true)))
        return -1;

    if (physdev && physdev[0])
        virFirewallAddRule(fw, layer,
                           "--table", "filter",
                           action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                           "LIBVIRT_FWI",
                           "--destination", networkstr,
                           "--in-interface", physdev,
                           "--out-interface", iface,
                           "--jump", "ACCEPT",
                           NULL);
    else
        virFirewallAddRule(fw, layer,
                           "--table", "filter",
                           action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                           "LIBVIRT_FWI",
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
int
iptablesAddForwardAllowIn(virFirewall *fw,
                          virSocketAddr *netaddr,
                          unsigned int prefix,
                          const char *iface,
                          const char *physdev)
{
    return iptablesForwardAllowIn(fw, netaddr, prefix, iface, physdev,
                                  VIR_NETFILTER_INSERT);
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
iptablesRemoveForwardAllowIn(virFirewall *fw,
                             virSocketAddr *netaddr,
                             unsigned int prefix,
                             const char *iface,
                             const char *physdev)
{
    return iptablesForwardAllowIn(fw, netaddr, prefix, iface, physdev,
                                  VIR_NETFILTER_DELETE);
}

static void
iptablesForwardAllowCross(virFirewall *fw,
                          virFirewallLayer layer,
                          const char *iface,
                          int action)
{
    virFirewallAddRule(fw, layer,
                       "--table", "filter",
                       action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                       "LIBVIRT_FWX",
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
void
iptablesAddForwardAllowCross(virFirewall *fw,
                             virFirewallLayer layer,
                             const char *iface)
{
    iptablesForwardAllowCross(fw, layer, iface, VIR_NETFILTER_INSERT);
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
void
iptablesRemoveForwardAllowCross(virFirewall *fw,
                                virFirewallLayer layer,
                                const char *iface)
{
    iptablesForwardAllowCross(fw, layer, iface, VIR_NETFILTER_DELETE);
}

static void
iptablesForwardRejectOut(virFirewall *fw,
                         virFirewallLayer layer,
                         const char *iface,
                         int action)
{
    virFirewallAddRule(fw, layer,
                       "--table", "filter",
                       action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                       "LIBVIRT_FWO",
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
void
iptablesAddForwardRejectOut(virFirewall *fw,
                            virFirewallLayer layer,
                            const char *iface)
{
    iptablesForwardRejectOut(fw, layer, iface, VIR_NETFILTER_INSERT);
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
void
iptablesRemoveForwardRejectOut(virFirewall *fw,
                               virFirewallLayer layer,
                               const char *iface)
{
    iptablesForwardRejectOut(fw, layer, iface, VIR_NETFILTER_DELETE);
}


static void
iptablesForwardRejectIn(virFirewall *fw,
                        virFirewallLayer layer,
                        const char *iface,
                        int action)
{
    virFirewallAddRule(fw, layer,
                       "--table", "filter",
                       action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                       "LIBVIRT_FWI",
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
void
iptablesAddForwardRejectIn(virFirewall *fw,
                           virFirewallLayer layer,
                           const char *iface)
{
    iptablesForwardRejectIn(fw, layer, iface, VIR_NETFILTER_INSERT);
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
void
iptablesRemoveForwardRejectIn(virFirewall *fw,
                              virFirewallLayer layer,
                              const char *iface)
{
    iptablesForwardRejectIn(fw, layer, iface, VIR_NETFILTER_DELETE);
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
                          int action)
{
    g_autofree char *networkstr = NULL;
    g_autofree char *addrStartStr = NULL;
    g_autofree char *addrEndStr = NULL;
    g_autofree char *portRangeStr = NULL;
    g_autofree char *natRangeStr = NULL;
    virFirewallRule *rule;
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
        rule = virFirewallAddRule(fw, layer,
                                  "--table", "nat",
                                  action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                                  "LIBVIRT_PRT",
                                  "--source", networkstr,
                                  "-p", protocol,
                                  "!", "--destination", networkstr,
                                  NULL);
    } else {
        rule = virFirewallAddRule(fw, layer,
                                  "--table", "nat",
                                  action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                                  "LIBVIRT_PRT",
                                  "--source", networkstr,
                                  "!", "--destination", networkstr,
                                  NULL);
    }

    if (physdev && physdev[0])
        virFirewallRuleAddArgList(fw, rule, "--out-interface", physdev, NULL);

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

        virFirewallRuleAddArgList(fw, rule,
                                  "--jump", "SNAT",
                                  "--to-source", natRangeStr, NULL);
    } else {
        virFirewallRuleAddArgList(fw, rule,
                                  "--jump", "MASQUERADE", NULL);

        if (portRangeStr && portRangeStr[0])
            virFirewallRuleAddArgList(fw, rule,
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
int
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
                                     VIR_NETFILTER_INSERT);
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
                                     VIR_NETFILTER_DELETE);
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
                              int action)
{
    g_autofree char *networkstr = NULL;
    virFirewallLayer layer = VIR_SOCKET_ADDR_FAMILY(netaddr) == AF_INET ?
        VIR_FIREWALL_LAYER_IPV4 : VIR_FIREWALL_LAYER_IPV6;

    if (!(networkstr = virSocketAddrFormatWithPrefix(netaddr, prefix, true)))
        return -1;

    if (physdev && physdev[0])
        virFirewallAddRule(fw, layer,
                           "--table", "nat",
                           action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                           "LIBVIRT_PRT",
                           "--out-interface", physdev,
                           "--source", networkstr,
                           "--destination", destaddr,
                           "--jump", "RETURN",
                           NULL);
    else
        virFirewallAddRule(fw, layer,
                           "--table", "nat",
                           action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                           "LIBVIRT_PRT",
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
int
iptablesAddDontMasquerade(virFirewall *fw,
                          virSocketAddr *netaddr,
                          unsigned int prefix,
                          const char *physdev,
                          const char *destaddr)
{
    return iptablesForwardDontMasquerade(fw, netaddr, prefix,
                                         physdev, destaddr, VIR_NETFILTER_INSERT);
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
int
iptablesRemoveDontMasquerade(virFirewall *fw,
                             virSocketAddr *netaddr,
                             unsigned int prefix,
                             const char *physdev,
                             const char *destaddr)
{
    return iptablesForwardDontMasquerade(fw, netaddr, prefix,
                                         physdev, destaddr,
                                         VIR_NETFILTER_DELETE);
}


static void
iptablesOutputFixUdpChecksum(virFirewall *fw,
                             const char *iface,
                             int port,
                             int action)
{
    g_autofree char *portstr = g_strdup_printf("%d", port);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "--table", "mangle",
                       action == VIR_NETFILTER_INSERT ? "--insert" : "--delete",
                       "LIBVIRT_PRT",
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
void
iptablesAddOutputFixUdpChecksum(virFirewall *fw,
                                const char *iface,
                                int port)
{
    iptablesOutputFixUdpChecksum(fw, iface, port, VIR_NETFILTER_INSERT);
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
void
iptablesRemoveOutputFixUdpChecksum(virFirewall *fw,
                                   const char *iface,
                                   int port)
{
    iptablesOutputFixUdpChecksum(fw, iface, port, VIR_NETFILTER_DELETE);
}
