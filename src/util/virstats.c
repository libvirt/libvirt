/*
 * virstats.c: Block and network stats.
 *
 * Copyright (C) 2007-2010, 2014 Red Hat, Inc.
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
 * Richard W.M. Jones <rjones@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>

#if defined(HAVE_GETIFADDRS) && defined(AF_LINK)
# include <net/if.h>
# include <ifaddrs.h>
#endif

#include "virerror.h"
#include "datatypes.h"
#include "virstats.h"
#include "viralloc.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_STATS_LINUX


/*-------------------- interface stats --------------------*/
/* Just reads the named interface, so not Xen or QEMU-specific.
 * NB. Caller must check that libvirt user is trying to query
 * the interface of a domain they own.  We do no such checking.
 */
#ifdef __linux__
int
virNetInterfaceStats(const char *path,
                     virDomainInterfaceStatsPtr stats)
{
    int path_len;
    FILE *fp;
    char line[256], *colon;

    fp = fopen("/proc/net/dev", "r");
    if (!fp) {
        virReportSystemError(errno, "%s",
                             _("Could not open /proc/net/dev"));
        return -1;
    }

    path_len = strlen(path);

    while (fgets(line, sizeof(line), fp)) {
        long long dummy;
        long long rx_bytes;
        long long rx_packets;
        long long rx_errs;
        long long rx_drop;
        long long tx_bytes;
        long long tx_packets;
        long long tx_errs;
        long long tx_drop;

        /* The line looks like:
         *   "   eth0:..."
         * Split it at the colon.
         */
        colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        if (colon-path_len >= line &&
            STREQ(colon-path_len, path)) {
            /* IMPORTANT NOTE!
             * /proc/net/dev vif<domid>.nn sees the network from the point
             * of view of dom0 / hypervisor.  So bytes TRANSMITTED by dom0
             * are bytes RECEIVED by the domain.  That's why the TX/RX fields
             * appear to be swapped here.
             */
            if (sscanf(colon+1,
                       "%lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld",
                       &tx_bytes, &tx_packets, &tx_errs, &tx_drop,
                       &dummy, &dummy, &dummy, &dummy,
                       &rx_bytes, &rx_packets, &rx_errs, &rx_drop,
                       &dummy, &dummy, &dummy, &dummy) != 16)
                continue;

            stats->rx_bytes = rx_bytes;
            stats->rx_packets = rx_packets;
            stats->rx_errs = rx_errs;
            stats->rx_drop = rx_drop;
            stats->tx_bytes = tx_bytes;
            stats->tx_packets = tx_packets;
            stats->tx_errs = tx_errs;
            stats->tx_drop = tx_drop;
            VIR_FORCE_FCLOSE(fp);

            return 0;
        }
    }
    VIR_FORCE_FCLOSE(fp);

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("/proc/net/dev: Interface not found"));
    return -1;
}
#elif defined(HAVE_GETIFADDRS) && defined(AF_LINK)
int
virNetInterfaceStats(const char *path,
                     virDomainInterfaceStatsPtr stats)
{
    struct ifaddrs *ifap, *ifa;
    struct if_data *ifd;
    int ret = -1;

    if (getifaddrs(&ifap) < 0) {
        virReportSystemError(errno, "%s",
                             _("Could not get interface list"));
        return -1;
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family != AF_LINK)
            continue;

        if (STREQ(ifa->ifa_name, path)) {
            ifd = (struct if_data *)ifa->ifa_data;
            stats->tx_bytes = ifd->ifi_ibytes;
            stats->tx_packets = ifd->ifi_ipackets;
            stats->tx_errs = ifd->ifi_ierrors;
            stats->tx_drop = ifd->ifi_iqdrops;
            stats->rx_bytes = ifd->ifi_obytes;
            stats->rx_packets = ifd->ifi_opackets;
            stats->rx_errs = ifd->ifi_oerrors;
# ifdef HAVE_STRUCT_IF_DATA_IFI_OQDROPS
            stats->rx_drop = ifd->ifi_oqdrops;
# else
            stats->rx_drop = 0;
# endif

            ret = 0;
            break;
        }
    }

    if (ret < 0)
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Interface not found"));

    freeifaddrs(ifap);
    return ret;
}
#else
int
virNetInterfaceStats(const char *path ATTRIBUTE_UNUSED,
                     virDomainInterfaceStatsPtr stats ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                   _("interface stats not implemented on this platform"));
    return -1;
}

#endif /* __linux__ */
