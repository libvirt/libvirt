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
static bool chainInitDone; /* true iff networkSetupPrivateChains was ever called */

static virErrorPtr errInitV4;
static virErrorPtr errInitV6;

/* Usually only called via virOnce, but can also be called directly in
 * response to firewalld reload (if chainInitDone == true)
 */
static void networkSetupPrivateChains(void)
{
    int rc;

    VIR_DEBUG("Setting up global firewall chains");

    g_clear_pointer(&errInitV4, virFreeError);
    g_clear_pointer(&errInitV6, virFreeError);

    rc = iptablesSetupPrivateChains(VIR_FIREWALL_LAYER_IPV4);
    if (rc < 0) {
        VIR_DEBUG("Failed to create global IPv4 chains: %s",
                  virGetLastErrorMessage());
        errInitV4 = virSaveLastError();
        virResetLastError();
    } else {
        if (rc)
            VIR_DEBUG("Created global IPv4 chains");
        else
            VIR_DEBUG("Global IPv4 chains already exist");
    }

    rc = iptablesSetupPrivateChains(VIR_FIREWALL_LAYER_IPV6);
    if (rc < 0) {
        VIR_DEBUG("Failed to create global IPv6 chains: %s",
                  virGetLastErrorMessage());
        errInitV6 = virSaveLastError();
        virResetLastError();
    } else {
        if (rc)
            VIR_DEBUG("Created global IPv6 chains");
        else
            VIR_DEBUG("Global IPv6 chains already exist");
    }

    chainInitDone = true;
}


static int
networkHasRunningNetworksWithFWHelper(virNetworkObj *obj,
                                void *opaque)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(obj);
    bool *activeWithFW = opaque;

    if (virNetworkObjIsActive(obj)) {
        virNetworkDef *def = virNetworkObjGetDef(obj);

        switch ((virNetworkForwardType) def->forward.type) {
        case VIR_NETWORK_FORWARD_NONE:
        case VIR_NETWORK_FORWARD_NAT:
        case VIR_NETWORK_FORWARD_ROUTE:
            *activeWithFW = true;
            break;

        case VIR_NETWORK_FORWARD_OPEN:
        case VIR_NETWORK_FORWARD_BRIDGE:
        case VIR_NETWORK_FORWARD_PRIVATE:
        case VIR_NETWORK_FORWARD_VEPA:
        case VIR_NETWORK_FORWARD_PASSTHROUGH:
        case VIR_NETWORK_FORWARD_HOSTDEV:
        case VIR_NETWORK_FORWARD_LAST:
            break;
        }
    }

    /*
     * terminate ForEach early once we find an active network that
     * adds Firewall rules (return status is ignored)
     */
    if (*activeWithFW)
        return -1;

    return 0;
}


static bool
networkHasRunningNetworksWithFW(virNetworkDriverState *driver)
{
    bool activeWithFW = false;

    virNetworkObjListForEach(driver->networks,
                             networkHasRunningNetworksWithFWHelper,
                             &activeWithFW);
    return activeWithFW;
}


void
networkPreReloadFirewallRules(virNetworkDriverState *driver,
                              bool startup G_GNUC_UNUSED,
                              bool force)
{
    /*
     * If there are any running networks, we need to
     * create the global rules upfront. This allows us
     * convert rules created by old libvirt into the new
     * format.
     *
     * If there are not any running networks, then we
     * must not create rules, because the rules will
     * cause the conntrack kernel module to be loaded.
     * This imposes a significant performance hit on
     * the networking stack. Thus we will only create
     * rules if a network is later startup.
     *
     * Any errors here are saved to be reported at time
     * of starting the network though as that makes them
     * more likely to be seen by a human
     */
    if (chainInitDone && force) {
        /* The Private chains have already been initialized once
         * during this run of libvirtd, so 1) we can't do it again via
         * virOnce(), and 2) we need to re-add the private chains even
         * if there are currently no running networks, because the
         * next time a network is started, libvirt will expect that
         * the chains have already been added. So we call directly
         * instead of via virOnce().
         */
        networkSetupPrivateChains();

    } else {
        if (!networkHasRunningNetworksWithFW(driver)) {
            VIR_DEBUG("Delayed global rule setup as no networks with firewall rules are running");
            return;
        }

        ignore_value(virOnce(&createdOnce, networkSetupPrivateChains));
    }
}


void networkPostReloadFirewallRules(bool startup G_GNUC_UNUSED)
{

}


/* XXX: This function can be a lot more exhaustive, there are certainly
 *      other scenarios where we can ruin host network connectivity.
 * XXX: Using a proper library is preferred over parsing /proc
 */
int networkCheckRouteCollision(virNetworkDef *def)
{
    int len;
    char *cur;
    g_autofree char *buf = NULL;
    /* allow for up to 100000 routes (each line is 128 bytes) */
    enum {MAX_ROUTE_SIZE = 128*100000};

    /* Read whole routing table into memory */
    if ((len = virFileReadAll(PROC_NET_ROUTE, MAX_ROUTE_SIZE, &buf)) < 0)
        return 0;

    /* Dropping the last character shouldn't hurt */
    if (len > 0)
        buf[len-1] = '\0';

    VIR_DEBUG("%s output:\n%s", PROC_NET_ROUTE, buf);

    if (!STRPREFIX(buf, "Iface"))
        return 0;

    /* First line is just headings, skip it */
    cur = strchr(buf, '\n');
    if (cur)
        cur++;

    while (cur) {
        char iface[17], dest[128], mask[128];
        unsigned int addr_val, mask_val;
        virNetworkIPDef *ipdef;
        virNetDevIPRoute *routedef;
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
                               _("Network is already in use by interface %1$s"),
                               iface);
                return -1;
            }
        }

        for (i = 0;
             (routedef = virNetworkDefGetRouteByIndex(def, AF_INET, i));
             i++) {

            virSocketAddr r_mask, r_addr;
            virSocketAddr *tmp_addr = virNetDevIPRouteGetAddress(routedef);
            int r_prefix = virNetDevIPRouteGetPrefix(routedef);

            if (!tmp_addr ||
                virSocketAddrMaskByPrefix(tmp_addr, r_prefix, &r_addr) < 0 ||
                virSocketAddrPrefixToNetmask(r_prefix, &r_mask, AF_INET) < 0)
                continue;

            if ((r_addr.data.inet4.sin_addr.s_addr == addr_val) &&
                (r_mask.data.inet4.sin_addr.s_addr == mask_val)) {
                g_autofree char *addr_str = virSocketAddrFormat(&r_addr);
                if (!addr_str)
                    virResetLastError();
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Route address '%1$s' conflicts with IP address for '%2$s'"),
                               NULLSTR(addr_str), iface);
                return -1;
            }
        }
    }

    return 0;
}

static const char networkLocalMulticastIPv4[] = "224.0.0.0/24";
static const char networkLocalMulticastIPv6[] = "ff02::/16";
static const char networkLocalBroadcast[] = "255.255.255.255/32";

static int
networkAddMasqueradingFirewallRules(virFirewall *fw,
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
networkRemoveMasqueradingFirewallRules(virFirewall *fw,
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
networkAddRoutingFirewallRules(virFirewall *fw,
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
networkRemoveRoutingFirewallRules(virFirewall *fw,
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
networkAddGeneralIPv4FirewallRules(virFirewall *fw,
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
networkRemoveGeneralIPv4FirewallRules(virFirewall *fw,
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
networkAddGeneralIPv6FirewallRules(virFirewall *fw,
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
networkRemoveGeneralIPv6FirewallRules(virFirewall *fw,
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
networkAddGeneralFirewallRules(virFirewall *fw,
                               virNetworkDef *def)
{
    networkAddGeneralIPv4FirewallRules(fw, def);
    networkAddGeneralIPv6FirewallRules(fw, def);
}


static void
networkRemoveGeneralFirewallRules(virFirewall *fw,
                                  virNetworkDef *def)
{
    networkRemoveGeneralIPv4FirewallRules(fw, def);
    networkRemoveGeneralIPv6FirewallRules(fw, def);
}

static void
networkAddChecksumFirewallRules(virFirewall *fw,
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
networkRemoveChecksumFirewallRules(virFirewall *fw,
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
networkAddIPSpecificFirewallRules(virFirewall *fw,
                                  virNetworkDef *def,
                                  virNetworkIPDef *ipdef)
{
    /* NB: in the case of IPv6, routing rules are added when the
     * forward mode is NAT. This is because IPv6 has no NAT.
     */

    if (def->forward.type == VIR_NETWORK_FORWARD_NAT) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET) ||
            def->forward.natIPv6 == VIR_TRISTATE_BOOL_YES)
            return networkAddMasqueradingFirewallRules(fw, def, ipdef);
        else if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            return networkAddRoutingFirewallRules(fw, def, ipdef);
    } else if (def->forward.type == VIR_NETWORK_FORWARD_ROUTE) {
        return networkAddRoutingFirewallRules(fw, def, ipdef);
    }
    return 0;
}


static int
networkRemoveIPSpecificFirewallRules(virFirewall *fw,
                                     virNetworkDef *def,
                                     virNetworkIPDef *ipdef)
{
    if (def->forward.type == VIR_NETWORK_FORWARD_NAT) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET) ||
            def->forward.natIPv6 == VIR_TRISTATE_BOOL_YES)
            return networkRemoveMasqueradingFirewallRules(fw, def, ipdef);
        else if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            return networkRemoveRoutingFirewallRules(fw, def, ipdef);
    } else if (def->forward.type == VIR_NETWORK_FORWARD_ROUTE) {
        return networkRemoveRoutingFirewallRules(fw, def, ipdef);
    }
    return 0;
}


/* Add all rules for all ip addresses (and general rules) on a network */
int networkAddFirewallRules(virNetworkDef *def)
{
    size_t i;
    virNetworkIPDef *ipdef;
    g_autoptr(virFirewall) fw = virFirewallNew();

    if (virOnce(&createdOnce, networkSetupPrivateChains) < 0)
        return -1;

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
                           _("zone %1$s requested for network %2$s but firewalld is not active"),
                           def->bridgeZone, def->name);
            return -1;
        }

        if (virFirewallDInterfaceSetZone(def->bridge, def->bridgeZone) < 0)
            return -1;

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
             *
             * Routed networks use a different zone and policy which we also
             * need to verify exist. Probing for the policy guarantees the
             * running firewalld has support for policies (firewalld >= 0.9.0).
             */
            if (def->forward.type == VIR_NETWORK_FORWARD_ROUTE &&
                virFirewallDPolicyExists("libvirt-routed-out") &&
                virFirewallDZoneExists("libvirt-routed")) {
                if (virFirewallDInterfaceSetZone(def->bridge, "libvirt-routed") < 0)
                    return -1;
            } else if (virFirewallDZoneExists("libvirt")) {
                if (virFirewallDInterfaceSetZone(def->bridge, "libvirt") < 0)
                    return -1;
            } else {
                unsigned long long version;
                int vresult = virFirewallDGetVersion(&version);

                if (vresult < 0)
                    return -1;

                /* Support for nftables backend was added in firewalld
                 * 0.6.0. Support for rule priorities (required by the
                 * 'libvirt' zone, which should be installed by a
                 * libvirt package, *not* by firewalld) was not added
                 * until firewalld 0.7.0 (unless it was backported).
                 */
                if (version >= 6000 &&
                    virFirewallDGetBackend() == VIR_FIREWALLD_BACKEND_NFTABLES) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("firewalld is set to use the nftables backend, but the required firewalld 'libvirt' zone is missing. Either set the firewalld backend to 'iptables', or ensure that firewalld has a 'libvirt' zone by upgrading firewalld to a version supporting rule priorities (0.7.0+) and/or rebuilding libvirt with --with-firewalld-zone"));
                    return -1;
                }
            }
        }
    }

    virFirewallStartTransaction(fw, 0);

    networkAddGeneralFirewallRules(fw, def);

    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i));
         i++) {
        if (networkAddIPSpecificFirewallRules(fw, def, ipdef) < 0)
            return -1;
    }

    virFirewallStartRollback(fw, 0);

    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i));
         i++) {
        if (networkRemoveIPSpecificFirewallRules(fw, def, ipdef) < 0)
            return -1;
    }
    networkRemoveGeneralFirewallRules(fw, def);

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);
    networkAddChecksumFirewallRules(fw, def);

    return virFirewallApply(fw);
}

/* Remove all rules for all ip addresses (and general rules) on a network */
void networkRemoveFirewallRules(virNetworkDef *def)
{
    size_t i;
    virNetworkIPDef *ipdef;
    g_autoptr(virFirewall) fw = virFirewallNew();

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);
    networkRemoveChecksumFirewallRules(fw, def);

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);

    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i));
         i++) {
        if (networkRemoveIPSpecificFirewallRules(fw, def, ipdef) < 0)
            return;
    }
    networkRemoveGeneralFirewallRules(fw, def);

    virFirewallApply(fw);
}
