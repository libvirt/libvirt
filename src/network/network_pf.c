/*
 * network_pf.c: pf-based firewall implementation for virtual networks
 *
 * Copyright (C) 2025 FreeBSD Foundation
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

/*
 * pf(4) configuration principles/assumptions.
 *
 * All libvirt-managed firewall rule are configured within a pf anchor.
 * Every libvirt network has a corresponding sub-anchor, like "libvirt/$network_name".
 * Libvirt does not create the root anchors, so users are expected to specify them in
 * their firewall configuration. Minimal configuration might look like:
 *
 * # cat /etc/pf.conf
 * scrub all
 *
 * nat-anchor "libvirt\*"
 * anchor "libvirt\*"
 *
 * pass all
 * #
 *
 * Users are not expected to add/modify rules in the "libvirt\*" subanchors because
 * the changes will be lost on restart.
 *
 * IPv6 NAT is currently not supported.
 */

#include <config.h>

#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#ifdef WITH_NET_IF_H
# include <net/if.h>
#endif
#include <sys/sysctl.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>

#include "internal.h"
#include "virfirewalld.h"
#include "vircommand.h"
#include "virerror.h"
#include "virlog.h"
#include "virhash.h"
#include "virenum.h"
#include "virstring.h"
#include "network_pf.h"

VIR_LOG_INIT("network.pf");

#define VIR_FROM_THIS VIR_FROM_NONE


static const char networkLocalMulticastIPv4[] = "224.0.0.0/24";
static const char networkLocalBroadcast[] = "255.255.255.255/32";


static char *
findDefaultRouteInterface(void)
{
    int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
    size_t needed;
    g_autofree char *buf = NULL;
    char *lim, *next;
    struct rt_msghdr *rtm;
    struct sockaddr *sa;
    struct sockaddr_in *sin;
    struct sockaddr_dl *sdl;
    char *ifname;
    size_t ifname_len;
    size_t i;

    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
        virReportSystemError(errno,
                             "%s",
                             _("Unable to get default interface name"));
        return NULL;
    }

    if (posix_memalign((void **)&buf, 8, needed) != 0) {
        virReportSystemError(errno,
                             "%s",
                             _("Unable to get default interface name"));
        return NULL;
    }

    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
        virReportSystemError(errno,
                             "%s",
                             _("Unable to get default interface name"));
        return NULL;
    }

    lim = buf + needed;
    next = buf;

    while (next < lim) {
        rtm = (struct rt_msghdr *)(void *)next;
        if (next + rtm->rtm_msglen > lim)
            break;

        sin = (struct sockaddr_in *)(rtm + 1);

        if ((rtm->rtm_flags & RTF_GATEWAY) && sin->sin_addr.s_addr == INADDR_ANY) {
            sdl = NULL;
            sa = (struct sockaddr *)(sin + 1);

            for (i = 1; i < RTAX_MAX; i++) {
                if (rtm->rtm_addrs & (1 << i)) {
                    if (i == RTAX_IFP && sa->sa_family == AF_LINK) {
                        sdl = (struct sockaddr_dl *)(void *)sa;
                        ifname_len = (sdl->sdl_nlen >= IFNAMSIZ) ? IFNAMSIZ - 1 : sdl->sdl_nlen;
                        ifname = g_new0(char, ifname_len + 1);
                        virStrcpy(ifname, sdl->sdl_data, ifname_len + 1);
                        return ifname;
                    }
                    sa = (struct sockaddr *)((char *)sa +
                         ((sa->sa_len > 0) ? sa->sa_len : sizeof(struct sockaddr)));
                }
            }
        }

        next += rtm->rtm_msglen;
    }

    return NULL;
}

static int
pfAddNatFirewallRules(virNetworkDef *def,
                      virNetworkIPDef *ipdef)
{
    /*
     * # NAT rules
     * table <natdst> persist
     *   { 0.0.0.0/0, ! 192.168.122.0/24, !224.0.0.0/24, !255.255.255.255 }
     * nat pass log on $ext_if from 192.168.122.0/24 to <natdst>
     *   -> ($ext_if) port 1024:65535
     *
     * # Filtering
     * pass log quick on virbr0 from 192.168.122.0/24 to 192.168.122.0/24
     * pass out log quick on virbr0 from 192.168.122.0/24 to 224.0.0.0/24
     * pass out log quick on virbr0 from 192.168.122.0/24 to 255.255.255.255
     * block log on virbr0
     */
    int prefix = virNetworkIPDefPrefix(ipdef);
    g_autofree const char *forwardIf = g_strdup(virNetworkDefForwardIf(def, 0));
    g_auto(virBuffer) pf_rules_buf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virCommand) cmd = virCommandNew(PFCTL);
    g_autoptr(virCommand) flush_cmd = virCommandNew(PFCTL);
    virPortRange *portRange = &def->forward.port;
    g_autofree char *portRangeStr = NULL;

    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid prefix or netmask for '%1$s'"),
                       def->bridge);
        return -1;
    }

    if (portRange->start == 0 && portRange->end == 0) {
        portRange->start = 1024;
        portRange->end = 65535;
    }

    if (portRange->start < portRange->end && portRange->end < 65536) {
        portRangeStr = g_strdup_printf("%u:%u",
                                       portRange->start,
                                       portRange->end);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid port range '%1$u-%2$u'."),
                       portRange->start, portRange->end);
        return -1;
    }

    if (!forwardIf) {
        forwardIf = findDefaultRouteInterface();
        if (!forwardIf) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s",
                           _("Cannot determine the default interface"));
            return -1;
        }
    }

    virBufferAsprintf(&pf_rules_buf,
                      "table <natdst> persist { 0.0.0.0/0, ! %s/%d, ! %s, ! %s }\n",
                      virSocketAddrFormat(&ipdef->address),
                      prefix,
                      networkLocalMulticastIPv4,
                      networkLocalBroadcast);
    virBufferAsprintf(&pf_rules_buf,
                      "nat pass on %s from %s/%d to <natdst> -> (%s) port %s\n",
                      forwardIf,
                      virSocketAddrFormat(&ipdef->address),
                      prefix,
                      forwardIf,
                      portRangeStr);
    virBufferAsprintf(&pf_rules_buf,
                      "pass quick on %s from %s/%d to %s/%d\n",
                      def->bridge,
                      virSocketAddrFormat(&ipdef->address),
                      prefix,
                      virSocketAddrFormat(&ipdef->address),
                      prefix);
    virBufferAsprintf(&pf_rules_buf,
                      "pass quick on %s from %s/%d to %s\n",
                      def->bridge,
                      virSocketAddrFormat(&ipdef->address),
                      prefix,
                      networkLocalMulticastIPv4);
    virBufferAsprintf(&pf_rules_buf,
                      "pass quick on %s from %s/%d to %s\n",
                      def->bridge,
                      virSocketAddrFormat(&ipdef->address),
                      prefix,
                      networkLocalBroadcast);
    virBufferAsprintf(&pf_rules_buf,
                      "block on %s\n",
                      def->bridge);

    /* pfctl -a libvirt/default -f - */
    virCommandAddArg(cmd, "-a");
    virCommandAddArgFormat(cmd, "libvirt/%s", def->name);
    virCommandAddArgList(cmd, "-f", "-", NULL);

    virCommandSetInputBuffer(cmd, virBufferContentAndReset(&pf_rules_buf));

    /* pfctl -a libvirt/default -F all */
    /* Flush rules as a separate command, so when it fails, e.g. because the
     * anchor didn't exist, we still proceed with rules creation */
    virCommandAddArg(flush_cmd, "-a");
    virCommandAddArgFormat(flush_cmd, "libvirt/%s", def->name);
    virCommandAddArgList(flush_cmd, "-F", "all", NULL);

    if (virCommandRun(flush_cmd, NULL) < 0) {
        VIR_WARN("Failed to flush firewall rules for network %s",
                 def->name);
    }

    if (virCommandRun(cmd, NULL) < 0) {
        VIR_WARN("Failed to create firewall rules for network %s",
                 def->name);
        return -1;
    }
    return 0;
}


static int
pfAddRoutingFirewallRules(virNetworkDef *def,
                          virNetworkIPDef *ipdef G_GNUC_UNUSED)
{
    int prefix = virNetworkIPDefPrefix(ipdef);

    if (prefix < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid prefix or netmask for '%1$s'"),
                       def->bridge);
        return -1;
    }

    /* TODO: routing rules */

    return 0;
}


static int
pfAddIPSpecificFirewallRules(virNetworkDef *def,
                             virNetworkIPDef *ipdef)
{
    if (def->forward.type == VIR_NETWORK_FORWARD_NAT) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET)) {
            return pfAddNatFirewallRules(def, ipdef);
        } else {
            virReportError(VIR_ERR_NO_SUPPORT, "%s",
                           _("Only IPv4 is supported"));
            return -1;
        }
    } else if (def->forward.type == VIR_NETWORK_FORWARD_ROUTE) {
        return pfAddRoutingFirewallRules(def, ipdef);
    }
    return 0;
}


int
pfAddFirewallRules(virNetworkDef *def)
{
    size_t i;
    virNetworkIPDef *ipdef;

    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i));
         i++) {
        if (pfAddIPSpecificFirewallRules(def, ipdef) < 0)
            return -1;
    }

    return 0;
}


void
pfRemoveFirewallRules(virNetworkDef *def)
{
    /* pfctl -a libvirt/default -F all */
    g_autoptr(virCommand) cmd = virCommandNew(PFCTL);
    virCommandAddArg(cmd, "-a");
    virCommandAddArgFormat(cmd, "libvirt/%s", def->name);
    virCommandAddArgList(cmd, "-F", "all", NULL);

    if (virCommandRun(cmd, NULL) < 0)
        VIR_WARN("Failed to remove firewall rules for network %s",
                 def->name);
}
