/*
 * bridge_driver_linux.c: Linux implementation of bridge driver
 *
 * Copyright (C) 2006-2013 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#include "viralloc.h"
#include "virfile.h"
#include "viriptables.h"
#include "virstring.h"
#include "virlog.h"
#include "virfirewall.h"
#include "virfirewalld.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("network.bridge_driver_linux");

#define PROC_NET_ROUTE "/proc/net/route"

static virOnceControl createdOnce;
static bool createdChains;
static virErrorPtr errInitV4;
static virErrorPtr errInitV6;

/* Only call via virOnce */
static void networkSetupPrivateChains(void)
{
    int rc;

    createdChains = false;

    rc = iptablesSetupPrivateChains(VIR_FIREWALL_LAYER_IPV4);
    if (rc < 0) {
        errInitV4 = virSaveLastError();
        virResetLastError();
    } else {
        virFreeError(errInitV4);
        errInitV4 = NULL;
        if (rc)
            createdChains = true;
    }

    rc = iptablesSetupPrivateChains(VIR_FIREWALL_LAYER_IPV6);
    if (rc < 0) {
        errInitV6 = virSaveLastError();
        virResetLastError();
    } else {
        virFreeError(errInitV6);
        errInitV6 = NULL;
        if (rc)
            createdChains = true;
    }
}

void networkPreReloadFirewallRules(bool startup)
{
    /* We create global rules upfront as we don't want
     * the perf hit of conditionally figuring out whether
     * to create them each time a network is started.
     *
     * Any errors here are saved to be reported at time
     * of starting the network though as that makes them
     * more likely to be seen by a human
     */
    ignore_value(virOnce(&createdOnce, networkSetupPrivateChains));

    /*
     * If this is initial startup, and we just created the
     * top level private chains we either
     *
     *   - upgraded from old libvirt
     *   - freshly booted from clean state
     *
     * In the first case we must delete the old rules from
     * the built-in chains, instead of our new private chains.
     * In the second case it doesn't matter, since no existing
     * rules will be present. Thus we can safely just tell it
     * to always delete from the builin chain
     */
    if (startup && createdChains)
        iptablesSetDeletePrivate(false);
}


void networkPostReloadFirewallRules(bool startup ATTRIBUTE_UNUSED)
{
    iptablesSetDeletePrivate(true);
}


/* XXX: This function can be a lot more exhaustive, there are certainly
 *      other scenarios where we can ruin host network connectivity.
 * XXX: Using a proper library is preferred over parsing /proc
 */
int networkCheckRouteCollision(virNetworkDefPtr def)
{
    int ret = 0, len;
    char *cur, *buf = NULL;
    /* allow for up to 100000 routes (each line is 128 bytes) */
    enum {MAX_ROUTE_SIZE = 128*100000};

    /* Read whole routing table into memory */
    if ((len = virFileReadAll(PROC_NET_ROUTE, MAX_ROUTE_SIZE, &buf)) < 0)
        goto out;

    /* Dropping the last character shouldn't hurt */
    if (len > 0)
        buf[len-1] = '\0';

    VIR_DEBUG("%s output:\n%s", PROC_NET_ROUTE, buf);

    if (!STRPREFIX(buf, "Iface"))
        goto out;

    /* First line is just headings, skip it */
    cur = strchr(buf, '\n');
    if (cur)
        cur++;

    while (cur) {
        char iface[17], dest[128], mask[128];
        unsigned int addr_val, mask_val;
        virNetworkIPDefPtr ipdef;
        virNetDevIPRoutePtr routedef;
        int num;
        size_t i;

        /* NUL-terminate the line, so sscanf doesn't go beyond a newline.  */
        char *nl = strchr(cur, '\n');
        if (nl)
            *nl++ = '\0';

        num = sscanf(cur, "%16s %127s %*s %*s %*s %*s %*s %127s",
                     iface, dest, mask);
        cur = nl;

        if (num != 3) {
            VIR_DEBUG("Failed to parse %s", PROC_NET_ROUTE);
            continue;
        }

        if (virStrToLong_ui(dest, NULL, 16, &addr_val) < 0) {
            VIR_DEBUG("Failed to convert network address %s to uint", dest);
            continue;
        }

        if (virStrToLong_ui(mask, NULL, 16, &mask_val) < 0) {
            VIR_DEBUG("Failed to convert network mask %s to uint", mask);
            continue;
        }

        addr_val &= mask_val;

        for (i = 0;
             (ipdef = virNetworkDefGetIPByIndex(def, AF_INET, i));
             i++) {

            unsigned int net_dest;
            virSocketAddr netmask;

            if (virNetworkIPDefNetmask(ipdef, &netmask) < 0) {
                VIR_WARN("Failed to get netmask of '%s'",
                         def->bridge);
                continue;
            }

            net_dest = (ipdef->address.data.inet4.sin_addr.s_addr &
                        netmask.data.inet4.sin_addr.s_addr);

            if ((net_dest == addr_val) &&
                (netmask.data.inet4.sin_addr.s_addr == mask_val)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Network is already in use by interface %s"),
                               iface);
                ret = -1;
                goto out;
            }
        }

        for (i = 0;
             (routedef = virNetworkDefGetRouteByIndex(def, AF_INET, i));
             i++) {

            virSocketAddr r_mask, r_addr;
            virSocketAddrPtr tmp_addr = virNetDevIPRouteGetAddress(routedef);
            int r_prefix = virNetDevIPRouteGetPrefix(routedef);

            if (!tmp_addr ||
                virSocketAddrMaskByPrefix(tmp_addr, r_prefix, &r_addr) < 0 ||
                virSocketAddrPrefixToNetmask(r_prefix, &r_mask, AF_INET) < 0)
                continue;

            if ((r_addr.data.inet4.sin_addr.s_addr == addr_val) &&
                (r_mask.data.inet4.sin_addr.s_addr == mask_val)) {
                char *addr_str = virSocketAddrFormat(&r_addr);
                if (!addr_str)
                    virResetLastError();
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Route address '%s' conflicts "
                                 "with IP address for '%s'"),
                               NULLSTR(addr_str), iface);
                VIR_FREE(addr_str);
                ret = -1;
                goto out;
            }
        }
    }

 out:
    VIR_FREE(buf);
    return ret;
}

static const char networkLocalMulticast[] = "224.0.0.0/24";
static const char networkLocalBroadcast[] = "255.255.255.255/32";

static int
networkAddMasqueradingFirewallRules(virFirewallPtr fw,
                                    virNetworkDefPtr def,
                                    virNetworkIPDefPtr ipdef)
{
    int prefix = virNetworkIPDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(def, 0);

    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid prefix or netmask for '%s'"),
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
    if (iptablesAddDontMasquerade(fw,
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
                                  networkLocalMulticast) < 0)
        return -1;

    return 0;
}

static int
networkRemoveMasqueradingFirewallRules(virFirewallPtr fw,
                                       virNetworkDefPtr def,
                                       virNetworkIPDefPtr ipdef)
{
    int prefix = virNetworkIPDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(def, 0);

    if (prefix < 0)
        return 0;

    if (iptablesRemoveDontMasquerade(fw,
                                     &ipdef->address,
                                     prefix,
                                     forwardIf,
                                     networkLocalMulticast) < 0)
        return -1;

    if (iptablesRemoveDontMasquerade(fw,
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
networkAddRoutingFirewallRules(virFirewallPtr fw,
                               virNetworkDefPtr def,
                               virNetworkIPDefPtr ipdef)
{
    int prefix = virNetworkIPDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(def, 0);

    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid prefix or netmask for '%s'"),
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
networkRemoveRoutingFirewallRules(virFirewallPtr fw,
                                  virNetworkDefPtr def,
                                  virNetworkIPDefPtr ipdef)
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
networkAddGeneralIPv4FirewallRules(virFirewallPtr fw,
                                   virNetworkDefPtr def)
{
    size_t i;
    virNetworkIPDefPtr ipv4def;

    /* First look for first IPv4 address that has dhcp or tftpboot defined. */
    /* We support dhcp config on 1 IPv4 interface only. */
    for (i = 0;
         (ipv4def = virNetworkDefGetIPByIndex(def, AF_INET, i));
         i++) {
        if (ipv4def->nranges || ipv4def->nhosts || ipv4def->tftproot)
            break;
    }

    /* allow DHCP requests through to dnsmasq */
    iptablesAddTcpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 67);
    iptablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 67);
    iptablesAddUdpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 68);

    /* allow DNS requests through to dnsmasq */
    iptablesAddTcpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);
    iptablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);

    /* allow TFTP requests through to dnsmasq if necessary */
    if (ipv4def && ipv4def->tftproot)
        iptablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 69);

    /* Catch all rules to block forwarding to/from bridges */
    iptablesAddForwardRejectOut(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);
    iptablesAddForwardRejectIn(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);

    /* Allow traffic between guests on the same bridge */
    iptablesAddForwardAllowCross(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);
}

static void
networkRemoveGeneralIPv4FirewallRules(virFirewallPtr fw,
                                      virNetworkDefPtr def)
{
    size_t i;
    virNetworkIPDefPtr ipv4def;

    for (i = 0;
         (ipv4def = virNetworkDefGetIPByIndex(def, AF_INET, i));
         i++) {
        if (ipv4def->nranges || ipv4def->nhosts || ipv4def->tftproot)
            break;
    }

    iptablesRemoveForwardAllowCross(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);
    iptablesRemoveForwardRejectIn(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);
    iptablesRemoveForwardRejectOut(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge);

    if (ipv4def && ipv4def->tftproot)
        iptablesRemoveUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 69);

    iptablesRemoveUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);
    iptablesRemoveTcpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 53);

    iptablesRemoveUdpOutput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 68);
    iptablesRemoveUdpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 67);
    iptablesRemoveTcpInput(fw, VIR_FIREWALL_LAYER_IPV4, def->bridge, 67);
}


/* Add all once/network rules required for IPv6.
 * If no IPv6 addresses are defined and <network ipv6='yes'> is
 * specified, then allow IPv6 communications between virtual systems.
 * If any IPv6 addresses are defined, then add the rules for regular operation.
 */
static void
networkAddGeneralIPv6FirewallRules(virFirewallPtr fw,
                                   virNetworkDefPtr def)
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
        /* allow DNS over IPv6 */
        iptablesAddTcpInput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
        iptablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 53);
        iptablesAddUdpInput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 547);
    }
}

static void
networkRemoveGeneralIPv6FirewallRules(virFirewallPtr fw,
                                      virNetworkDefPtr def)
{
    if (!virNetworkDefGetIPByIndex(def, AF_INET6, 0) &&
        !def->ipv6nogw) {
        return;
    }

    if (virNetworkDefGetIPByIndex(def, AF_INET6, 0)) {
        iptablesRemoveUdpInput(fw, VIR_FIREWALL_LAYER_IPV6, def->bridge, 547);
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
networkAddGeneralFirewallRules(virFirewallPtr fw,
                               virNetworkDefPtr def)
{
    networkAddGeneralIPv4FirewallRules(fw, def);
    networkAddGeneralIPv6FirewallRules(fw, def);
}


static void
networkRemoveGeneralFirewallRules(virFirewallPtr fw,
                                  virNetworkDefPtr def)
{
    networkRemoveGeneralIPv4FirewallRules(fw, def);
    networkRemoveGeneralIPv6FirewallRules(fw, def);
}

static void
networkAddChecksumFirewallRules(virFirewallPtr fw,
                                virNetworkDefPtr def)
{
    size_t i;
    virNetworkIPDefPtr ipv4def;

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
networkRemoveChecksumFirewallRules(virFirewallPtr fw,
                                   virNetworkDefPtr def)
{
    size_t i;
    virNetworkIPDefPtr ipv4def;

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
networkAddIPSpecificFirewallRules(virFirewallPtr fw,
                                  virNetworkDefPtr def,
                                  virNetworkIPDefPtr ipdef)
{
    /* NB: in the case of IPv6, routing rules are added when the
     * forward mode is NAT. This is because IPv6 has no NAT.
     */

    if (def->forward.type == VIR_NETWORK_FORWARD_NAT) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET))
            return networkAddMasqueradingFirewallRules(fw, def, ipdef);
        else if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            return networkAddRoutingFirewallRules(fw, def, ipdef);
    } else if (def->forward.type == VIR_NETWORK_FORWARD_ROUTE) {
        return networkAddRoutingFirewallRules(fw, def, ipdef);
    }
    return 0;
}


static int
networkRemoveIPSpecificFirewallRules(virFirewallPtr fw,
                                     virNetworkDefPtr def,
                                     virNetworkIPDefPtr ipdef)
{
    if (def->forward.type == VIR_NETWORK_FORWARD_NAT) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET))
            return networkRemoveMasqueradingFirewallRules(fw, def, ipdef);
        else if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            return networkRemoveRoutingFirewallRules(fw, def, ipdef);
    } else if (def->forward.type == VIR_NETWORK_FORWARD_ROUTE) {
        return networkRemoveRoutingFirewallRules(fw, def, ipdef);
    }
    return 0;
}


/* Add all rules for all ip addresses (and general rules) on a network */
int networkAddFirewallRules(virNetworkDefPtr def)
{
    size_t i;
    virNetworkIPDefPtr ipdef;
    virFirewallPtr fw = NULL;
    int ret = -1;

    if (errInitV4 &&
        (virNetworkDefGetIPByIndex(def, AF_INET, 0) ||
         virNetworkDefGetRouteByIndex(def, AF_INET, 0))) {
        virSetError(errInitV4);
        return -1;
    }

    if (errInitV6 &&
        (virNetworkDefGetIPByIndex(def, AF_INET6, 0) ||
         virNetworkDefGetRouteByIndex(def, AF_INET6, 0) ||
         def->ipv6nogw)) {
        virSetError(errInitV6);
        return -1;
    }

    if (def->bridgeZone) {

        /* if a firewalld zone has been specified, fail/log an error
         * if we can't honor it
         */
        if (virFirewallDIsRegistered() < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("zone %s requested for network %s "
                             "but firewalld is not active"),
                           def->bridgeZone, def->name);
            goto cleanup;
        }

        if (virFirewallDInterfaceSetZone(def->bridge, def->bridgeZone) < 0)
            goto cleanup;

    } else {

        /* if firewalld is active, try to set the "libvirt" zone. This is
         * desirable (for consistency) if firewalld is using the iptables
         * backend, but is necessary (for basic network connectivity) if
         * firewalld is using the nftables backend
         */
        if (virFirewallDIsRegistered() == 0) {

            /* if the "libvirt" zone exists, then set it. If not, and
             * if firewalld is using the nftables backend, then we
             * need to log an error because the combination of
             * nftables + default zone means that traffic cannot be
             * forwarded (and even DHCP and DNS from guest to host
             * will probably no be permitted by the default zone
             */
            if (virFirewallDZoneExists("libvirt")) {
                if (virFirewallDInterfaceSetZone(def->bridge, "libvirt") < 0)
                    goto cleanup;
            } else {
                unsigned long version;
                int vresult = virFirewallDGetVersion(&version);

                if (vresult < 0)
                    goto cleanup;

                /* Support for nftables backend was added in firewalld
                 * 0.6.0. Support for rule priorities (required by the
                 * 'libvirt' zone, which should be installed by a
                 * libvirt package, *not* by firewalld) was not added
                 * until firewalld 0.7.0 (unless it was backported).
                 */
                if (version >= 6000 &&
                    virFirewallDGetBackend() == VIR_FIREWALLD_BACKEND_NFTABLES) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("firewalld is set to use the nftables "
                                     "backend, but the required firewalld "
                                     "'libvirt' zone is missing. Either set "
                                     "the firewalld backend to 'iptables', or "
                                     "ensure that firewalld has a 'libvirt' "
                                     "zone by upgrading firewalld to a "
                                     "version supporting rule priorities "
                                     "(0.7.0+) and/or rebuilding "
                                     "libvirt with --with-firewalld-zone"));
                    goto cleanup;
                }
            }
        }
    }

    fw = virFirewallNew();

    virFirewallStartTransaction(fw, 0);

    networkAddGeneralFirewallRules(fw, def);

    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i));
         i++) {
        if (networkAddIPSpecificFirewallRules(fw, def, ipdef) < 0)
            goto cleanup;
    }

    virFirewallStartRollback(fw, 0);

    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i));
         i++) {
        if (networkRemoveIPSpecificFirewallRules(fw, def, ipdef) < 0)
            goto cleanup;
    }
    networkRemoveGeneralFirewallRules(fw, def);

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);
    networkAddChecksumFirewallRules(fw, def);

    if (virFirewallApply(fw) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virFirewallFree(fw);
    return ret;
}

/* Remove all rules for all ip addresses (and general rules) on a network */
void networkRemoveFirewallRules(virNetworkDefPtr def)
{
    size_t i;
    virNetworkIPDefPtr ipdef;
    virFirewallPtr fw = NULL;

    fw = virFirewallNew();

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);
    networkRemoveChecksumFirewallRules(fw, def);

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);

    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i));
         i++) {
        if (networkRemoveIPSpecificFirewallRules(fw, def, ipdef) < 0)
            goto cleanup;
    }
    networkRemoveGeneralFirewallRules(fw, def);

    virFirewallApply(fw);

 cleanup:
    virFirewallFree(fw);
}
