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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "viralloc.h"
#include "virfile.h"
#include "viriptables.h"
#include "virstring.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("network.bridge_driver_linux");

#define PROC_NET_ROUTE "/proc/net/route"

/* XXX: This function can be a lot more exhaustive, there are certainly
 *      other scenarios where we can ruin host network connectivity.
 * XXX: Using a proper library is preferred over parsing /proc
 */
int networkCheckRouteCollision(virNetworkObjPtr network)
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
        virNetworkIpDefPtr ipdef;
        int num;
        size_t i;

        /* NUL-terminate the line, so sscanf doesn't go beyond a newline.  */
        char *nl = strchr(cur, '\n');
        if (nl) {
            *nl++ = '\0';
        }

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
             (ipdef = virNetworkDefGetIpByIndex(network->def, AF_INET, i));
             i++) {

            unsigned int net_dest;
            virSocketAddr netmask;

            if (virNetworkIpDefNetmask(ipdef, &netmask) < 0) {
                VIR_WARN("Failed to get netmask of '%s'",
                         network->def->bridge);
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
    }

 out:
    VIR_FREE(buf);
    return ret;
}

static const char networkLocalMulticast[] = "224.0.0.0/24";
static const char networkLocalBroadcast[] = "255.255.255.255/32";

static int
networkAddMasqueradingFirewallRules(virNetworkObjPtr network,
                                    virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(network->def, 0);

    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid prefix or netmask for '%s'"),
                       network->def->bridge);
        goto masqerr1;
    }

    /* allow forwarding packets from the bridge interface */
    if (iptablesAddForwardAllowOut(&ipdef->address,
                                   prefix,
                                   network->def->bridge,
                                   forwardIf) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow forwarding from '%s'"),
                       network->def->bridge);
        goto masqerr1;
    }

    /* allow forwarding packets to the bridge interface if they are
     * part of an existing connection
     */
    if (iptablesAddForwardAllowRelatedIn(&ipdef->address,
                                         prefix,
                                         network->def->bridge,
                                         forwardIf) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow forwarding to '%s'"),
                       network->def->bridge);
        goto masqerr2;
    }

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
    if (iptablesAddForwardMasquerade(&ipdef->address,
                                     prefix,
                                     forwardIf,
                                     &network->def->forward.addr,
                                     &network->def->forward.port,
                                     NULL) < 0) {
        if (forwardIf)
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to enable masquerading to %s"),
                           forwardIf);
        else
            virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                           _("failed to add iptables rule to enable masquerading"));
        goto masqerr3;
    }

    /* UDP with a source port restriction */
    if (iptablesAddForwardMasquerade(&ipdef->address,
                                     prefix,
                                     forwardIf,
                                     &network->def->forward.addr,
                                     &network->def->forward.port,
                                     "udp") < 0) {
        if (forwardIf)
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to enable UDP masquerading to %s"),
                           forwardIf);
        else
            virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                           _("failed to add iptables rule to enable UDP masquerading"));
        goto masqerr4;
    }

    /* TCP with a source port restriction */
    if (iptablesAddForwardMasquerade(&ipdef->address,
                                     prefix,
                                     forwardIf,
                                     &network->def->forward.addr,
                                     &network->def->forward.port,
                                     "tcp") < 0) {
        if (forwardIf)
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to enable TCP masquerading to %s"),
                           forwardIf);
        else
            virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                           _("failed to add iptables rule to enable TCP masquerading"));
        goto masqerr5;
    }

    /* exempt local network broadcast address as destination */
    if (iptablesAddDontMasquerade(&ipdef->address,
                                  prefix,
                                  forwardIf,
                                  networkLocalBroadcast) < 0) {
        if (forwardIf)
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to prevent local broadcast masquerading on %s"),
                           forwardIf);
        else
            virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                           _("failed to add iptables rule to prevent local broadcast masquerading"));
        goto masqerr6;
    }

    /* exempt local multicast range as destination */
    if (iptablesAddDontMasquerade(&ipdef->address,
                                  prefix,
                                  forwardIf,
                                  networkLocalMulticast) < 0) {
        if (forwardIf)
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to add iptables rule to prevent local multicast masquerading on %s"),
                           forwardIf);
        else
            virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                           _("failed to add iptables rule to prevent local multicast masquerading"));
        goto masqerr7;
    }

    return 0;

 masqerr7:
    iptablesRemoveDontMasquerade(&ipdef->address,
                                 prefix,
                                 forwardIf,
                                 networkLocalBroadcast);
 masqerr6:
    iptablesRemoveForwardMasquerade(&ipdef->address,
                                    prefix,
                                    forwardIf,
                                    &network->def->forward.addr,
                                    &network->def->forward.port,
                                    "tcp");
 masqerr5:
    iptablesRemoveForwardMasquerade(&ipdef->address,
                                    prefix,
                                    forwardIf,
                                    &network->def->forward.addr,
                                    &network->def->forward.port,
                                    "udp");
 masqerr4:
    iptablesRemoveForwardMasquerade(&ipdef->address,
                                    prefix,
                                    forwardIf,
                                    &network->def->forward.addr,
                                    &network->def->forward.port,
                                    NULL);
 masqerr3:
    iptablesRemoveForwardAllowRelatedIn(&ipdef->address,
                                        prefix,
                                        network->def->bridge,
                                        forwardIf);
 masqerr2:
    iptablesRemoveForwardAllowOut(&ipdef->address,
                                  prefix,
                                  network->def->bridge,
                                  forwardIf);
 masqerr1:
    return -1;
}

static void
networkRemoveMasqueradingFirewallRules(virNetworkObjPtr network,
                                       virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(network->def, 0);

    if (prefix >= 0) {
        iptablesRemoveDontMasquerade(&ipdef->address,
                                     prefix,
                                     forwardIf,
                                     networkLocalMulticast);
        iptablesRemoveDontMasquerade(&ipdef->address,
                                     prefix,
                                     forwardIf,
                                     networkLocalBroadcast);
        iptablesRemoveForwardMasquerade(&ipdef->address,
                                        prefix,
                                        forwardIf,
                                        &network->def->forward.addr,
                                        &network->def->forward.port,
                                        "tcp");
        iptablesRemoveForwardMasquerade(&ipdef->address,
                                        prefix,
                                        forwardIf,
                                        &network->def->forward.addr,
                                        &network->def->forward.port,
                                        "udp");
        iptablesRemoveForwardMasquerade(&ipdef->address,
                                        prefix,
                                        forwardIf,
                                        &network->def->forward.addr,
                                        &network->def->forward.port,
                                        NULL);

        iptablesRemoveForwardAllowRelatedIn(&ipdef->address,
                                            prefix,
                                            network->def->bridge,
                                            forwardIf);
        iptablesRemoveForwardAllowOut(&ipdef->address,
                                      prefix,
                                      network->def->bridge,
                                      forwardIf);
    }
}

static int
networkAddRoutingFirewallRules(virNetworkObjPtr network,
                               virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(network->def, 0);

    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid prefix or netmask for '%s'"),
                       network->def->bridge);
        goto routeerr1;
    }

    /* allow routing packets from the bridge interface */
    if (iptablesAddForwardAllowOut(&ipdef->address,
                                   prefix,
                                   network->def->bridge,
                                   forwardIf) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow routing from '%s'"),
                       network->def->bridge);
        goto routeerr1;
    }

    /* allow routing packets to the bridge interface */
    if (iptablesAddForwardAllowIn(&ipdef->address,
                                  prefix,
                                  network->def->bridge,
                                  forwardIf) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow routing to '%s'"),
                       network->def->bridge);
        goto routeerr2;
    }

    return 0;

 routeerr2:
    iptablesRemoveForwardAllowOut(&ipdef->address,
                                  prefix,
                                  network->def->bridge,
                                  forwardIf);
 routeerr1:
    return -1;
}


static void
networkRemoveRoutingFirewallRules(virNetworkObjPtr network,
                                  virNetworkIpDefPtr ipdef)
{
    int prefix = virNetworkIpDefPrefix(ipdef);
    const char *forwardIf = virNetworkDefForwardIf(network->def, 0);

    if (prefix >= 0) {
        iptablesRemoveForwardAllowIn(&ipdef->address,
                                     prefix,
                                     network->def->bridge,
                                     forwardIf);

        iptablesRemoveForwardAllowOut(&ipdef->address,
                                      prefix,
                                      network->def->bridge,
                                      forwardIf);
    }
}

/* Add all once/network rules required for IPv6.
 * If no IPv6 addresses are defined and <network ipv6='yes'> is
 * specified, then allow IPv6 commuinications between virtual systems.
 * If any IPv6 addresses are defined, then add the rules for regular operation.
 */
static int
networkAddGeneralIp6tablesRules(virNetworkObjPtr network)
{

    if (!virNetworkDefGetIpByIndex(network->def, AF_INET6, 0) &&
        !network->def->ipv6nogw) {
        return 0;
    }

    /* Catch all rules to block forwarding to/from bridges */

    if (iptablesAddForwardRejectOut(AF_INET6, network->def->bridge) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add ip6tables rule to block outbound traffic from '%s'"),
                       network->def->bridge);
        goto err1;
    }

    if (iptablesAddForwardRejectIn(AF_INET6, network->def->bridge) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add ip6tables rule to block inbound traffic to '%s'"),
                       network->def->bridge);
        goto err2;
    }

    /* Allow traffic between guests on the same bridge */
    if (iptablesAddForwardAllowCross(AF_INET6, network->def->bridge) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add ip6tables rule to allow cross bridge traffic on '%s'"),
                       network->def->bridge);
        goto err3;
    }

    /* if no IPv6 addresses are defined, we are done. */
    if (!virNetworkDefGetIpByIndex(network->def, AF_INET6, 0))
        return 0;

    /* allow DNS over IPv6 */
    if (iptablesAddTcpInput(AF_INET6, network->def->bridge, 53) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add ip6tables rule to allow DNS requests from '%s'"),
                       network->def->bridge);
        goto err4;
    }

    if (iptablesAddUdpInput(AF_INET6, network->def->bridge, 53) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add ip6tables rule to allow DNS requests from '%s'"),
                       network->def->bridge);
        goto err5;
    }

    if (iptablesAddUdpInput(AF_INET6, network->def->bridge, 547) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add ip6tables rule to allow DHCP6 requests from '%s'"),
                       network->def->bridge);
        goto err6;
    }

    return 0;

    /* unwind in reverse order from the point of failure */
 err6:
    iptablesRemoveUdpInput(AF_INET6, network->def->bridge, 53);
 err5:
    iptablesRemoveTcpInput(AF_INET6, network->def->bridge, 53);
 err4:
    iptablesRemoveForwardAllowCross(AF_INET6, network->def->bridge);
 err3:
    iptablesRemoveForwardRejectIn(AF_INET6, network->def->bridge);
 err2:
    iptablesRemoveForwardRejectOut(AF_INET6, network->def->bridge);
 err1:
    return -1;
}

static void
networkRemoveGeneralIp6tablesRules(virNetworkObjPtr network)
{
    if (!virNetworkDefGetIpByIndex(network->def, AF_INET6, 0) &&
        !network->def->ipv6nogw) {
        return;
    }
    if (virNetworkDefGetIpByIndex(network->def, AF_INET6, 0)) {
        iptablesRemoveUdpInput(AF_INET6, network->def->bridge, 547);
        iptablesRemoveUdpInput(AF_INET6, network->def->bridge, 53);
        iptablesRemoveTcpInput(AF_INET6, network->def->bridge, 53);
    }

    /* the following rules are there if no IPv6 address has been defined
     * but network->def->ipv6nogw == true
     */
    iptablesRemoveForwardAllowCross(AF_INET6, network->def->bridge);
    iptablesRemoveForwardRejectIn(AF_INET6, network->def->bridge);
    iptablesRemoveForwardRejectOut(AF_INET6, network->def->bridge);
}


static int
networkAddGeneralFirewallRules(virNetworkObjPtr network)
{
    size_t i;
    virNetworkIpDefPtr ipv4def;

    /* First look for first IPv4 address that has dhcp or tftpboot defined. */
    /* We support dhcp config on 1 IPv4 interface only. */
    for (i = 0;
         (ipv4def = virNetworkDefGetIpByIndex(network->def, AF_INET, i));
         i++) {
        if (ipv4def->nranges || ipv4def->nhosts || ipv4def->tftproot)
            break;
    }

    /* allow DHCP requests through to dnsmasq */

    if (iptablesAddTcpInput(AF_INET, network->def->bridge, 67) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow DHCP requests from '%s'"),
                       network->def->bridge);
        goto err1;
    }

    if (iptablesAddUdpInput(AF_INET, network->def->bridge, 67) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow DHCP requests from '%s'"),
                       network->def->bridge);
        goto err2;
    }

    if (iptablesAddUdpOutput(AF_INET, network->def->bridge, 68) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow DHCP replies to '%s'"),
                       network->def->bridge);
        goto err3;
    }

    /* If we are doing local DHCP service on this network, attempt to
     * add a rule that will fixup the checksum of DHCP response
     * packets back to the guests (but report failure without
     * aborting, since not all iptables implementations support it).
     */

    if (ipv4def && (ipv4def->nranges || ipv4def->nhosts) &&
        (iptablesAddOutputFixUdpChecksum(network->def->bridge, 68) < 0)) {
        VIR_WARN("Could not add rule to fixup DHCP response checksums "
                 "on network '%s'.", network->def->name);
        VIR_WARN("May need to update iptables package & kernel to support CHECKSUM rule.");
    }

    /* allow DNS requests through to dnsmasq */
    if (iptablesAddTcpInput(AF_INET, network->def->bridge, 53) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow DNS requests from '%s'"),
                       network->def->bridge);
        goto err4;
    }

    if (iptablesAddUdpInput(AF_INET, network->def->bridge, 53) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow DNS requests from '%s'"),
                       network->def->bridge);
        goto err5;
    }

    /* allow TFTP requests through to dnsmasq if necessary */
    if (ipv4def && ipv4def->tftproot &&
        iptablesAddUdpInput(AF_INET, network->def->bridge, 69) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow TFTP requests from '%s'"),
                       network->def->bridge);
        goto err6;
    }

    /* Catch all rules to block forwarding to/from bridges */

    if (iptablesAddForwardRejectOut(AF_INET, network->def->bridge) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to block outbound traffic from '%s'"),
                       network->def->bridge);
        goto err7;
    }

    if (iptablesAddForwardRejectIn(AF_INET, network->def->bridge) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to block inbound traffic to '%s'"),
                       network->def->bridge);
        goto err8;
    }

    /* Allow traffic between guests on the same bridge */
    if (iptablesAddForwardAllowCross(AF_INET, network->def->bridge) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("failed to add iptables rule to allow cross bridge traffic on '%s'"),
                       network->def->bridge);
        goto err9;
    }

    /* add IPv6 general rules, if needed */
    if (networkAddGeneralIp6tablesRules(network) < 0) {
        goto err10;
    }

    return 0;

    /* unwind in reverse order from the point of failure */
 err10:
    iptablesRemoveForwardAllowCross(AF_INET, network->def->bridge);
 err9:
    iptablesRemoveForwardRejectIn(AF_INET, network->def->bridge);
 err8:
    iptablesRemoveForwardRejectOut(AF_INET, network->def->bridge);
 err7:
    if (ipv4def && ipv4def->tftproot) {
        iptablesRemoveUdpInput(AF_INET, network->def->bridge, 69);
    }
 err6:
    iptablesRemoveUdpInput(AF_INET, network->def->bridge, 53);
 err5:
    iptablesRemoveTcpInput(AF_INET, network->def->bridge, 53);
 err4:
    iptablesRemoveUdpOutput(AF_INET, network->def->bridge, 68);
 err3:
    iptablesRemoveUdpInput(AF_INET, network->def->bridge, 67);
 err2:
    iptablesRemoveTcpInput(AF_INET, network->def->bridge, 67);
 err1:
    return -1;
}


static void
networkRemoveGeneralFirewallRules(virNetworkObjPtr network)
{
    size_t i;
    virNetworkIpDefPtr ipv4def;

    networkRemoveGeneralIp6tablesRules(network);

    for (i = 0;
         (ipv4def = virNetworkDefGetIpByIndex(network->def, AF_INET, i));
         i++) {
        if (ipv4def->nranges || ipv4def->nhosts || ipv4def->tftproot)
            break;
    }

    iptablesRemoveForwardAllowCross(AF_INET, network->def->bridge);
    iptablesRemoveForwardRejectIn(AF_INET, network->def->bridge);
    iptablesRemoveForwardRejectOut(AF_INET, network->def->bridge);
    if (ipv4def && ipv4def->tftproot) {
        iptablesRemoveUdpInput(AF_INET, network->def->bridge, 69);
    }
    iptablesRemoveUdpInput(AF_INET, network->def->bridge, 53);
    iptablesRemoveTcpInput(AF_INET, network->def->bridge, 53);
    if (ipv4def && (ipv4def->nranges || ipv4def->nhosts)) {
        iptablesRemoveOutputFixUdpChecksum(network->def->bridge, 68);
    }
    iptablesRemoveUdpOutput(AF_INET, network->def->bridge, 68);
    iptablesRemoveUdpInput(AF_INET, network->def->bridge, 67);
    iptablesRemoveTcpInput(AF_INET, network->def->bridge, 67);
}


static int
networkAddIpSpecificFirewallRules(virNetworkObjPtr network,
                                  virNetworkIpDefPtr ipdef)
{
    /* NB: in the case of IPv6, routing rules are added when the
     * forward mode is NAT. This is because IPv6 has no NAT.
     */

    if (network->def->forward.type == VIR_NETWORK_FORWARD_NAT) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET))
            return networkAddMasqueradingFirewallRules(network, ipdef);
        else if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            return networkAddRoutingFirewallRules(network, ipdef);
    } else if (network->def->forward.type == VIR_NETWORK_FORWARD_ROUTE) {
        return networkAddRoutingFirewallRules(network, ipdef);
    }
    return 0;
}


static void
networkRemoveIpSpecificFirewallRules(virNetworkObjPtr network,
                                     virNetworkIpDefPtr ipdef)
{
    if (network->def->forward.type == VIR_NETWORK_FORWARD_NAT) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET))
            networkRemoveMasqueradingFirewallRules(network, ipdef);
        else if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET6))
            networkRemoveRoutingFirewallRules(network, ipdef);
    } else if (network->def->forward.type == VIR_NETWORK_FORWARD_ROUTE) {
        networkRemoveRoutingFirewallRules(network, ipdef);
    }
}


/* Add all rules for all ip addresses (and general rules) on a network */
int networkAddFirewallRules(virNetworkObjPtr network)
{
    size_t i, j;
    virNetworkIpDefPtr ipdef;
    virErrorPtr orig_error;

    /* Add "once per network" rules */
    if (networkAddGeneralFirewallRules(network) < 0)
        return -1;

    for (i = 0;
         (ipdef = virNetworkDefGetIpByIndex(network->def, AF_UNSPEC, i));
         i++) {
        /* Add address-specific iptables rules */
        if (networkAddIpSpecificFirewallRules(network, ipdef) < 0) {
            goto err;
        }
    }
    return 0;

 err:
    /* store the previous error message before attempting removal of rules */
    orig_error = virSaveLastError();

    /* The final failed call to networkAddIpSpecificFirewallRules will
     * have removed any rules it created, but we need to remove those
     * added for previous IP addresses.
     */
    for (j = 0; j < i; j++) {
        if ((ipdef = virNetworkDefGetIpByIndex(network->def, AF_UNSPEC, j)))
            networkRemoveIpSpecificFirewallRules(network, ipdef);
    }
    networkRemoveGeneralFirewallRules(network);

    /* return the original error */
    virSetError(orig_error);
    virFreeError(orig_error);
    return -1;
}

/* Remove all rules for all ip addresses (and general rules) on a network */
void networkRemoveFirewallRules(virNetworkObjPtr network)
{
    size_t i;
    virNetworkIpDefPtr ipdef;

    for (i = 0;
         (ipdef = virNetworkDefGetIpByIndex(network->def, AF_UNSPEC, i));
         i++) {
        networkRemoveIpSpecificFirewallRules(network, ipdef);
    }
    networkRemoveGeneralFirewallRules(network);
}
