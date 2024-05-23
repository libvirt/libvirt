/*
 * network_nftables.c: nftables-based firewall implementation for
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
#include "virstring.h"
#include "network_nftables.h"

VIR_LOG_INIT("network.nftables");

#define VIR_FROM_THIS VIR_FROM_NONE

#ifdef VIR_NFTABLES_INCLUDE_HOST_RULES
/* The input and output tables aren't currently used */
# define VIR_NFTABLES_INPUT_CHAIN "guest_to_host"
# define VIR_NFTABLES_OUTPUT_CHAIN "host_to_guest"
#endif

#define VIR_NFTABLES_FORWARD_CHAIN "forward"
#define VIR_NFTABLES_FWD_IN_CHAIN "guest_input"
#define VIR_NFTABLES_FWD_OUT_CHAIN "guest_output"
#define VIR_NFTABLES_FWD_X_CHAIN "guest_cross"
#define VIR_NFTABLES_NAT_POSTROUTE_CHAIN "guest_nat"

/* we must avoid using the standard "filter" table as used by
 * iptables, as any subsequent attempts to use iptables commands will
 * fail (due to the "filter" table having rules that are unexpected by
 * the iptables-compat
 */

#define VIR_NFTABLES_PRIVATE_TABLE "libvirt_network"

/* nftables backend uses the same binary (nft) for all layers, but
 * IPv4 and IPv6 have their rules in separate classes of tables,
 * either "ip" or "ip6". (there is also an "inet" class of tables that
 * would examined for both IPv4 and IPv6 traffic, but since we want
 * different rules for each family, we only use the family-specific
 * table classes).
 */
VIR_ENUM_DECL(nftablesLayer);
VIR_ENUM_IMPL(nftablesLayer,
              VIR_FIREWALL_LAYER_LAST,
              "",
              "ip",
              "ip6",
);


typedef struct {
    const char *parent;
    const char *child;
    const char *extraArgs;
} nftablesGlobalChain;

typedef struct {
    virFirewallLayer layer;
    nftablesGlobalChain *chains;
    size_t nchains;
    bool *changed;
} nftablesGlobalChainData;


nftablesGlobalChain nftablesChains[] = {
    /* chains for filter rules */

#ifdef VIR_NFTABLES_INCLUDE_HOST_RULES
    /* nothing is being added to these chains now, so they are effective NOPs */
    {NULL, VIR_NFTABLES_INPUT_CHAIN, "{ type filter hook input priority 0; policy accept; }"},
    {NULL, VIR_NFTABLES_OUTPUT_CHAIN, "{ type filter hook output priority 0; policy accept; }"},
#endif

    {NULL, VIR_NFTABLES_FORWARD_CHAIN, "{ type filter hook forward priority 0; policy accept; }"},
    {VIR_NFTABLES_FORWARD_CHAIN, VIR_NFTABLES_FWD_OUT_CHAIN, NULL},
    {VIR_NFTABLES_FORWARD_CHAIN, VIR_NFTABLES_FWD_IN_CHAIN, NULL},
    {VIR_NFTABLES_FORWARD_CHAIN, VIR_NFTABLES_FWD_X_CHAIN, NULL},

    /* chains for NAT rules */
    {NULL, VIR_NFTABLES_NAT_POSTROUTE_CHAIN, "{ type nat hook postrouting priority 100; policy accept; }"},
};


static int
nftablesPrivateChainCreate(virFirewall *fw,
                           virFirewallLayer layer,
                           const char *const *lines,
                           void *opaque)
{
    nftablesGlobalChainData *data = opaque;
    g_autoptr(GHashTable) chains = virHashNew(NULL);
    g_autoptr(GHashTable) links = virHashNew(NULL);
    const char *const *line;
    const char *chain = NULL;
    size_t i;
    bool tableMatch = false;
    const char *layerStr = nftablesLayerTypeToString(layer);
    g_autofree char *tableStr = g_strdup_printf("table %s %s {",
                                                layerStr,
                                                VIR_NFTABLES_PRIVATE_TABLE);

    line = lines;
    while (line && *line) {
        const char *pos = *line;

        virSkipSpaces(&pos);
        if (STREQ(pos, tableStr)) {
            /* "table ip libvirt {" */

            tableMatch = true;

        } else if (STRPREFIX(pos, "chain ")) {
            /* "chain LIBVIRT_OUT {" */

            chain = pos + 6;
            pos = strchr(chain, ' ');
            if (pos) {
                *(char *)pos = '\0';
                if (virHashUpdateEntry(chains, chain, (void *)0x1) < 0)
                    return -1;
            }

        } else if ((pos = strstr(pos, "jump "))) {
            /* "counter packets 20189046 bytes 3473108889 jump LIBVIRT_OUT" */

            pos += 5;
            if (chain) {
                if (virHashUpdateEntry(links, pos, (char *)chain) < 0)
                    return -1;
            }

        }
        line++;
    }

    if (!tableMatch) {
        virFirewallAddCmd(fw, layer, "add", "table",
                          layerStr, VIR_NFTABLES_PRIVATE_TABLE, NULL);
    }

    for (i = 0; i < data->nchains; i++) {
        if (!(tableMatch && virHashLookup(chains, data->chains[i].child))) {
            virFirewallAddCmd(fw, layer, "add", "chain",
                              layerStr, VIR_NFTABLES_PRIVATE_TABLE,
                              data->chains[i].child,
                              data->chains[i].extraArgs, NULL);
            *data->changed = true;
        }

        if (data->chains[i].parent) {
            const char *from = virHashLookup(links, data->chains[i].child);

            if (!from || STRNEQ(from, data->chains[i].parent)) {
                virFirewallAddCmd(fw, layer, "insert", "rule",
                                  layerStr, VIR_NFTABLES_PRIVATE_TABLE,
                                  data->chains[i].parent, "counter",
                                  "jump", data->chains[i].child, NULL);
            }
        }
    }

    return 0;
}


int
nftablesSetupPrivateChains(virFirewallLayer layer)
{
    bool changed = false;
    g_autoptr(virFirewall) fw = virFirewallNew(VIR_FIREWALL_BACKEND_NFTABLES);
    const char *layerStr =  nftablesLayerTypeToString(layer);
    nftablesGlobalChainData data =  { layer, nftablesChains, G_N_ELEMENTS(nftablesChains), &changed };

    virFirewallStartTransaction(fw, 0);

    /* the output of "nft list table ip[6] libvirt" will be parsed by
     * the callback nftablesPrivateChainCreate which will add any
     * needed commands to add missing chains (or possibly even add the
     * "ip[6] libvirt" table itself
     */
    virFirewallAddCmdFull(fw, layer, false,
                          nftablesPrivateChainCreate, &data,
                          "list", "table",
                          layerStr, VIR_NFTABLES_PRIVATE_TABLE, NULL);

    if (virFirewallApply(fw) < 0)
        return -1;

    return changed ? 1 : 0;
}


#ifdef VIR_NFTABLES_INCLUDE_HOST_RULES
/* currently these functions aren't used, but they remain in the
 * source (uncompiled) as examples of adding specific rules to permit
 * input/output of packets. in case the need arises in the future
 */
static void
nftablesAddInput(virFirewall *fw,
                 virFirewallLayer layer,
                 const char *iface,
                 int port,
                 int tcp)
{
    g_autofree char *portstr = g_strdup_printf("%d", port);
    const char *layerStr =  nftablesLayerTypeToString(layer);

    virFirewallAddCmd(fw, layer, "insert", "rule",
                      layerStr, VIR_NFTABLES_PRIVATE_TABLE,
                      VIR_NFTABLES_INPUT_CHAIN,
                      "iif", iface,
                      tcp ? "tcp" : "udp",
                      "dport", portstr,
                      "counter", "accept",
                      NULL);
}


static void
nftablesAddOutput(virFirewall *fw,
                  virFirewallLayer layer,
                  const char *iface,
                  int port,
                  int tcp)
{
    g_autofree char *portstr = g_strdup_printf("%d", port);
    const char *layerStr = nftablesLayerTypeToString(layer);

    virFirewallAddCmd(fw, layer, "insert", "rule",
                      layerStr, VIR_NFTABLES_PRIVATE_TABLE,
                      VIR_NFTABLES_OUTPUT_CHAIN,
                      "oif", iface,
                      tcp ? "tcp" : "udp",
                      "dport", portstr,
                      "counter", "accept",
                      NULL);
}


/**
 * nftablesAddTcpInput:
 *
 * Add a rule to @fw that will allow incoming TCP sessions to port
 * @port on @iface with protocol @layer.
 */
static void
nftablesAddTcpInput(virFirewall *fw,
                    virFirewallLayer layer,
                    const char *iface,
                    int port)
{
    nftablesAddInput(fw, layer, iface, port, 1);
}


/**
 * nftablesAddUdpInput:
 *
 * Add a rule to @fw that will allow incoming UDP sessions to port
 * @port on @iface with protocol @layer.
 */
static void
nftablesAddUdpInput(virFirewall *fw,
                    virFirewallLayer layer,
                    const char *iface,
                    int port)
{
    nftablesAddInput(fw, layer, iface, port, 0);
}


/**
 * nftablesAddTcpOutput:
 *
 * Add a rule to @fw that will allow outbound TCP sessions to port
 * @port on @iface with protocol @layer.
 */
static void
nftablesAddTcpOutput(virFirewall *fw,
                     virFirewallLayer layer,
                     const char *iface,
                     int port)
{
    nftablesAddOutput(fw, layer, iface, port, 1);
}


/**
 * nftablesAddUdpOutput:
 *
 * Add a rule to @fw that will allow outbound UDP sessions to port
 * @port on @iface with protocol @layer.
 */
static void
nftablesAddUdpOutput(virFirewall *fw,
                     virFirewallLayer layer,
                     const char *iface,
                     int port)
{
    nftablesAddOutput(fw, layer, iface, port, 0);
}


#endif


/**
 * nftablesAddForwardAllowOut:
 *
 * Add a rule to @fw that allows all outbound traffic coming from
 * @iface (the virtual network's bridge) to be forwarded out @physdev,
 * as long as its source address is in @netaddr/@prefix.
 */
static int
nftablesAddForwardAllowOut(virFirewall *fw,
                           virSocketAddr *netaddr,
                           unsigned int prefix,
                           const char *iface,
                           const char *physdev)
{
    g_autofree char *networkstr = NULL;
    virFirewallLayer layer = VIR_SOCKET_ADDR_FAMILY(netaddr) == AF_INET ?
        VIR_FIREWALL_LAYER_IPV4 : VIR_FIREWALL_LAYER_IPV6;
    const char *layerStr = nftablesLayerTypeToString(layer);
    virFirewallCmd *fwCmd;

    if (!(networkstr = virSocketAddrFormatWithPrefix(netaddr, prefix, true)))
        return -1;

    fwCmd = virFirewallAddCmd(fw, layer, "insert", "rule",
                              layerStr, VIR_NFTABLES_PRIVATE_TABLE,
                              VIR_NFTABLES_FWD_OUT_CHAIN,
                              layerStr, "saddr", networkstr,
                              "iif", iface, NULL);

    if (physdev && physdev[0])
        virFirewallCmdAddArgList(fw, fwCmd, "oif", physdev, NULL);

    virFirewallCmdAddArgList(fw, fwCmd, "counter", "accept", NULL);

    return 0;
}

/**
 * nftablesAddForwardAllowRelatedIn:
 *
 * Add a rule to @fw that allows all traffic coming in from @physdev
 * and destined to @iface (the virtual network's bridge) that has a
 * destination within @netaddr/@prefix and is associated with an
 * existing connection.
 */
static int
nftablesAddForwardAllowRelatedIn(virFirewall *fw,
                                 virSocketAddr *netaddr,
                                 unsigned int prefix,
                                 const char *iface,
                                 const char *physdev)
{
    virFirewallLayer layer = VIR_SOCKET_ADDR_FAMILY(netaddr) == AF_INET ?
        VIR_FIREWALL_LAYER_IPV4 : VIR_FIREWALL_LAYER_IPV6;
    const char *layerStr =  nftablesLayerTypeToString(layer);
    g_autofree char *networkstr = NULL;
    virFirewallCmd *fwCmd;

    if (!(networkstr = virSocketAddrFormatWithPrefix(netaddr, prefix, true)))
        return -1;

    fwCmd = virFirewallAddCmd(fw, layer, "insert", "rule",
                              layerStr, VIR_NFTABLES_PRIVATE_TABLE,
                              VIR_NFTABLES_FWD_IN_CHAIN, NULL);

    if (physdev && physdev[0])
        virFirewallCmdAddArgList(fw, fwCmd, "iif", physdev, NULL);

    virFirewallCmdAddArgList(fw, fwCmd, "oif", iface,
                             layerStr, "daddr", networkstr,
                             "ct", "state", "related,established",
                             "counter", "accept", NULL);
    return 0;
}


/**
 * nftablesAddForwardAllowIn:
 *
 * Add a rule to @fw that allows all traffic coming in from @physdev
 * and destined to @iface (the virtual network's bridge) that has a
 * destination within @netaddr/@prefix.
 */
static int
nftablesAddForwardAllowIn(virFirewall *fw,
                          virSocketAddr *netaddr,
                          unsigned int prefix,
                          const char *iface,
                          const char *physdev)
{
    virFirewallLayer layer = VIR_SOCKET_ADDR_FAMILY(netaddr) == AF_INET ?
        VIR_FIREWALL_LAYER_IPV4 : VIR_FIREWALL_LAYER_IPV6;
    const char *layerStr =  nftablesLayerTypeToString(layer);
    g_autofree char *networkstr = NULL;
    virFirewallCmd *fwCmd;

    if (!(networkstr = virSocketAddrFormatWithPrefix(netaddr, prefix, true)))
        return -1;

    fwCmd = virFirewallAddCmd(fw, layer, "insert", "rule",
                             layerStr, VIR_NFTABLES_PRIVATE_TABLE,
                             VIR_NFTABLES_FWD_IN_CHAIN,
                             layerStr, "daddr", networkstr, NULL);

    if (physdev && physdev[0])
        virFirewallCmdAddArgList(fw, fwCmd, "iif", physdev, NULL);

    virFirewallCmdAddArgList(fw, fwCmd, "oif", iface,
                              "counter", "accept", NULL);
    return 0;
}


/**
 * nftablesAddForwardAllowCross:
 *
 * Add a rule to @fw to allow traffic to go across @iface (the virtual
 * network's bridge) from one port to another. This allows all traffic
 * between guests on the same virtual network.
 */
static void
nftablesAddForwardAllowCross(virFirewall *fw,
                             virFirewallLayer layer,
                             const char *iface)
{
    virFirewallAddCmd(fw, layer, "insert", "rule",
                      nftablesLayerTypeToString(layer),
                      VIR_NFTABLES_PRIVATE_TABLE,
                      VIR_NFTABLES_FWD_X_CHAIN,
                      "iif", iface,
                      "oif", iface,
                      "counter", "accept",
                      NULL);
}


/**
 * nftablesAddForwardRejectOut:
 *
 * Add a rule to @fw to forbid all outbound traffic through @iface
 * (the virtual network's bridge). This is used as a catchall rule to
 * reject traffic that hasn't already been explicitly allowed by
 * another rule.
 */
static void
nftablesAddForwardRejectOut(virFirewall *fw,
                            virFirewallLayer layer,
                            const char *iface)
{
    virFirewallAddCmd(fw, layer, "insert", "rule",
                      nftablesLayerTypeToString(layer),
                      VIR_NFTABLES_PRIVATE_TABLE,
                      VIR_NFTABLES_FWD_OUT_CHAIN,
                      "iif", iface,
                      "counter", "reject",
                      NULL);
}


/**
 * nftablesAddForwardRejectIn:
 *
 * Add a rule to @fw to forbid all inbound traffic through @iface (the
 * virtual network's bridge). This is used as a catchall rule to
 * reject traffic that hasn't already been explicitly allowed by
 * another rule.
 */
static void
nftablesAddForwardRejectIn(virFirewall *fw,
                           virFirewallLayer layer,
                           const char *iface)
{
    virFirewallAddCmd(fw, layer, "insert", "rule",
                      nftablesLayerTypeToString(layer),
                      VIR_NFTABLES_PRIVATE_TABLE,
                      VIR_NFTABLES_FWD_IN_CHAIN,
                      "oif", iface,
                      "counter", "reject",
                      NULL);
}


/**
 * nftablesAddForwardMasquerade:
 *
 * Add a rule to @fw that will masquerade outbound traffic from
 * @netaddr/@prefix @iface to have the source IP/port from one of the
 * range of @addr:@port (or something appropriate for the interface
 * used for egress, if no address/port range is given)
 */
static int
nftablesAddForwardMasquerade(virFirewall *fw,
                             virSocketAddr *netaddr,
                             unsigned int prefix,
                             const char *physdev,
                             virSocketAddrRange *addr,
                             virPortRange *port,
                             const char *protocol)
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
    const char *layerStr =  nftablesLayerTypeToString(layer);

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

    fwCmd = virFirewallAddCmd(fw, layer, "insert", "rule",
                              layerStr, VIR_NFTABLES_PRIVATE_TABLE,
                              VIR_NFTABLES_NAT_POSTROUTE_CHAIN, NULL);

    if (protocol && protocol[0])
        virFirewallCmdAddArgList(fw, fwCmd, "meta", "l4proto", protocol, NULL);

    virFirewallCmdAddArgList(fw, fwCmd,
                             layerStr, "saddr", networkstr,
                             layerStr, "daddr", "!=", networkstr, NULL);

    if (physdev && physdev[0])
        virFirewallCmdAddArgList(fw, fwCmd, "oif", physdev, NULL);

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

    /* Use snat if public address is specified */
    if (addrStartStr && addrStartStr[0]) {
        if (addrEndStr && addrEndStr[0]) {
            natRangeStr = g_strdup_printf("%s-%s%s", addrStartStr, addrEndStr,
                                          portRangeStr ? portRangeStr : "");
        } else {
            natRangeStr = g_strdup_printf("%s%s", addrStartStr,
                                          portRangeStr ? portRangeStr : "");
        }

        virFirewallCmdAddArgList(fw, fwCmd, "counter", "snat", "to", natRangeStr, NULL);
    } else {
        virFirewallCmdAddArgList(fw, fwCmd, "counter", "masquerade", NULL);

        if (portRangeStr && portRangeStr[0])
            virFirewallCmdAddArgList(fw, fwCmd, "to", portRangeStr, NULL);
    }

    return 0;
}


/**
 * nftablesAddDontMasquerade:
 *
 * Add a rule to @fw that prevents masquerading traffic coming from
 * the network associated with the bridge if said traffic targets
 * @destaddr.
 */
static int
nftablesAddDontMasquerade(virFirewall *fw,
                          virSocketAddr *netaddr,
                          unsigned int prefix,
                          const char *physdev,
                          const char *destaddr)
{
    g_autofree char *networkstr = NULL;
    virFirewallLayer layer = VIR_SOCKET_ADDR_FAMILY(netaddr) == AF_INET ?
        VIR_FIREWALL_LAYER_IPV4 : VIR_FIREWALL_LAYER_IPV6;
    const char *layerStr =  nftablesLayerTypeToString(layer);
    virFirewallCmd *fwCmd;

    if (!(networkstr = virSocketAddrFormatWithPrefix(netaddr, prefix, true)))
        return -1;

    fwCmd = virFirewallAddCmd(fw, layer, "insert", "rule",
                              layerStr, VIR_NFTABLES_PRIVATE_TABLE,
                              VIR_NFTABLES_NAT_POSTROUTE_CHAIN, NULL);

    if (physdev && physdev[0])
        virFirewallCmdAddArgList(fw, fwCmd, "oif", physdev, NULL);

    virFirewallCmdAddArgList(fw, fwCmd,
                             layerStr, "saddr", networkstr,
                             layerStr, "daddr", destaddr,
                             "counter", "return", NULL);
    return 0;
}


static const char networkLocalMulticastIPv4[] = "224.0.0.0/24";
static const char networkLocalMulticastIPv6[] = "ff02::/16";
static const char networkLocalBroadcast[] = "255.255.255.255/32";


static int
nftablesAddMasqueradingFirewallRules(virFirewall *fw,
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
    if (nftablesAddForwardAllowOut(fw,
                                   &ipdef->address,
                                   prefix,
                                   def->bridge,
                                   forwardIf) < 0)
        return -1;

    /* allow forwarding packets to the bridge interface if they are
     * part of an existing connection
     */
    if (nftablesAddForwardAllowRelatedIn(fw,
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
     * The sport mappings are required, because default Nftables
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
    if (nftablesAddForwardMasquerade(fw,
                                     &ipdef->address,
                                     prefix,
                                     forwardIf,
                                     &def->forward.addr,
                                     &def->forward.port,
                                     NULL) < 0)
        return -1;

    /* UDP with a source port restriction */
    if (nftablesAddForwardMasquerade(fw,
                                     &ipdef->address,
                                     prefix,
                                     forwardIf,
                                     &def->forward.addr,
                                     &def->forward.port,
                                     "udp") < 0)
        return -1;

    /* TCP with a source port restriction */
    if (nftablesAddForwardMasquerade(fw,
                                     &ipdef->address,
                                     prefix,
                                     forwardIf,
                                     &def->forward.addr,
                                     &def->forward.port,
                                     "tcp") < 0)
        return -1;

    /* exempt local network broadcast address as destination */
    if (isIPv4 &&
        nftablesAddDontMasquerade(fw,
                                  &ipdef->address,
                                  prefix,
                                  forwardIf,
                                  networkLocalBroadcast) < 0)
        return -1;

    /* exempt local multicast range as destination */
    if (nftablesAddDontMasquerade(fw,
                                  &ipdef->address,
                                  prefix,
                                  forwardIf,
                                  isIPv4 ? networkLocalMulticastIPv4 :
                                  networkLocalMulticastIPv6) < 0)
        return -1;

    return 0;
}


static int
nftablesAddRoutingFirewallRules(virFirewall *fw,
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
    if (nftablesAddForwardAllowOut(fw,
                                   &ipdef->address,
                                   prefix,
                                   def->bridge,
                                   forwardIf) < 0)
        return -1;

    /* allow routing packets to the bridge interface */
    if (nftablesAddForwardAllowIn(fw,
                                  &ipdef->address,
                                  prefix,
                                  def->bridge,
                                  forwardIf) < 0)
        return -1;

    return 0;
}


static void
nftablesAddGeneralIPv4FirewallRules(virFirewall *fw,
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

#ifdef VIR_NFTABLES_INCLUDE_HOST_RULES
    /* These rules copied from the iptables backend, have been removed
     * from the nftab because they are redundant since we are using our own
     * table that is default accept; there are no other users that
     * could add a reject rule that we would need to / be able to
     * override with these rules
     */

    /* allow DHCP requests through to dnsmasq & back out */
    nftablesAddTcpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 67);
    nftablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 67);
    nftablesAddTcpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 68);
    nftablesAddUdpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 68);

    /* allow DNS requests through to dnsmasq & back out */
    nftablesAddTcpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);
    nftablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);
    nftablesAddTcpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);
    nftablesAddUdpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);

    /* allow TFTP requests through to dnsmasq if necessary & back out */
    if (ipv4def && ipv4def->tftproot) {
        nftablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 69);
        nftablesAddUdpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 69);
    }
#endif

    /* Catch all rules to block forwarding to/from bridges */
    nftablesAddForwardRejectOut(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);
    nftablesAddForwardRejectIn(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);

    /* Allow traffic between guests on the same bridge */
    nftablesAddForwardAllowCross(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);
}


/* Add all once/network rules required for IPv6.
 * If no IPv6 addresses are defined and <network ipv6='yes'> is
 * specified, then allow IPv6 communications between virtual systems.
 * If any IPv6 addresses are defined, then add the rules for regular operation.
 */
static void
nftablesAddGeneralIPv6FirewallRules(virFirewall *fw,
                                    virNetworkDef *def)
{
    if (!virNetworkDefGetIPByIndex(def, AF_INET6, 0) &&
        !def->ipv6nogw) {
        return;
    }

    /* Catch all rules to block forwarding to/from bridges */
    nftablesAddForwardRejectOut(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge);
    nftablesAddForwardRejectIn(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge);

    /* Allow traffic between guests on the same bridge */
    nftablesAddForwardAllowCross(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge);

#ifdef VIR_NFTABLES_INCLUDE_HOST_RULES
    /* see the note above in nftablesAddGeneralIPv4FirewallRules */

    if (virNetworkDefGetIPByIndex(def, AF_INET6, 0)) {
        /* allow DNS over IPv6 & back out */
        nftablesAddTcpInput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
        nftablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
        nftablesAddTcpOutput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
        nftablesAddUdpOutput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
        /* allow DHCPv6 & back out */
        nftablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 547);
        nftablesAddUdpOutput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 546);
    }
#endif
}


static void
nftablesAddGeneralFirewallRules(virFirewall *fw,
                                virNetworkDef *def)
{
    nftablesAddGeneralIPv4FirewallRules(fw, def);
    nftablesAddGeneralIPv6FirewallRules(fw, def);
}


static int
nftablesAddIPSpecificFirewallRules(virFirewall *fw,
                                   virNetworkDef *def,
                                   virNetworkIPDef *ipdef)
{
    /* NB: in the case of IPv6, routing rules are added when the
     * forward mode is NAT. This is because IPv6 has no NAT.
     */

    if (def->forward.type == VIR_NETWORK_FORWARD_NAT) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET) ||
            def->forward.natIPv6 == VIR_TRISTATE_BOOL_YES)
            return nftablesAddMasqueradingFirewallRules(fw, def, ipdef);
        else if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            return nftablesAddRoutingFirewallRules(fw, def, ipdef);
    } else if (def->forward.type == VIR_NETWORK_FORWARD_ROUTE) {
        return nftablesAddRoutingFirewallRules(fw, def, ipdef);
    }
    return 0;
}


/* nftablesAddFirewallrules:
 *
 * @def - the network that needs an nftables firewall added
 * @fwRemoval - if this is not NULL, it points to a pointer
 *    that should be filled in with a virFirewall object containing
 *    all the commands needed to remove this firewall at a later time.
 *
 * Add all rules for all ip addresses (and general rules) on a
 * network, and optionally return a virFirewall object containing all
 * the rules needed to later remove the firewall that has been added.
 */
int
nftablesAddFirewallRules(virNetworkDef *def, virFirewall **fwRemoval)
{
    size_t i;
    virNetworkIPDef *ipdef;
    g_autoptr(virFirewall) fw = virFirewallNew(VIR_FIREWALL_BACKEND_NFTABLES);

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_AUTO_ROLLBACK);

    nftablesAddGeneralFirewallRules(fw, def);

    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i));
         i++) {
        if (nftablesAddIPSpecificFirewallRules(fw, def, ipdef) < 0)
            return -1;
    }

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
