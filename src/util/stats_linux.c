/*
 * Linux block and network stats.
 *
 * Copyright (C) 2007-2010 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Richard W.M. Jones <rjones@redhat.com>
 */

#include <config.h>

/* This file only applies on Linux. */
#ifdef __linux__

# include <stdio.h>
# include <stdlib.h>
# include <fcntl.h>
# include <string.h>
# include <unistd.h>
# include <regex.h>

# include "virterror_internal.h"
# include "datatypes.h"
# include "util.h"
# include "stats_linux.h"
# include "memory.h"
# include "virfile.h"

# define VIR_FROM_THIS VIR_FROM_STATS_LINUX

# define virStatsError(code, ...)                               \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,         \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


/*-------------------- interface stats --------------------*/
/* Just reads the named interface, so not Xen or QEMU-specific.
 * NB. Caller must check that libvirt user is trying to query
 * the interface of a domain they own.  We do no such checking.
 */

int
linuxDomainInterfaceStats(const char *path,
                          struct _virDomainInterfaceStats *stats)
{
    int path_len;
    FILE *fp;
    char line[256], *colon;

    fp = fopen ("/proc/net/dev", "r");
    if (!fp) {
        virReportSystemError(errno, "%s",
                             _("Could not open /proc/net/dev"));
        return -1;
    }

    path_len = strlen (path);

    while (fgets (line, sizeof(line), fp)) {
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
        colon = strchr (line, ':');
        if (!colon) continue;
        *colon = '\0';
        if (colon-path_len >= line &&
            STREQ (colon-path_len, path)) {
            /* IMPORTANT NOTE!
             * /proc/net/dev vif<domid>.nn sees the network from the point
             * of view of dom0 / hypervisor.  So bytes TRANSMITTED by dom0
             * are bytes RECEIVED by the domain.  That's why the TX/RX fields
             * appear to be swapped here.
             */
            if (sscanf (colon+1,
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
            VIR_FORCE_FCLOSE (fp);

            return 0;
        }
    }
    VIR_FORCE_FCLOSE(fp);

    virStatsError(VIR_ERR_INTERNAL_ERROR,
                  _("/proc/net/dev: Interface not found"));
    return -1;
}

#endif /* __linux__ */
