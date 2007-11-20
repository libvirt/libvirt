/*
 * Linux block and network stats.
 *
 * Copyright (C) 2007 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Richard W.M. Jones <rjones@redhat.com>
 */

#include "config.h"

/* This file only applies on Linux. */
#ifdef __linux__

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_XEN
#include <xs.h>
#endif

#include "internal.h"
#include "xen_unified.h"
#include "stats_linux.h"

/**
 * statsErrorFunc:
 * @conn: the connection
 * @error: the error number
 * @func: the function failing
 * @info: extra information string
 * @value: extra information number
 *
 * Handle a stats error.
 */
static void
statsErrorFunc (virConnectPtr conn,
                virErrorNumber error, const char *func, const char *info,
                int value)
{
    char fullinfo[1000];
    const char *errmsg;

    errmsg = __virErrorMsg(error, info);
    if (func != NULL) {
        snprintf(fullinfo, sizeof (fullinfo) - 1, "%s: %s", func, info);
        fullinfo[sizeof (fullinfo) - 1] = 0;
        info = fullinfo;
    }
    __virRaiseError(conn, NULL, NULL, VIR_FROM_STATS_LINUX, error,
                    VIR_ERR_ERROR,
                    errmsg, info, NULL, value, 0, errmsg, info,
                    value);
}

#ifdef WITH_XEN
/*-------------------- Xen: block stats --------------------*/

#include <linux/major.h>

/* This is normally defined in <linux/major.h> but previously we
 * hard-coded it.  So if it's not defined, hard-code again.
 */
#ifndef XENVBD_MAJOR
#define XENVBD_MAJOR 202
#endif

static int
xstrtoint64 (char const *s, int base, int64_t *result)
{
    long long int lli;
    char *p;

    errno = 0;
    lli = strtoll (s, &p, base);
    if (errno || !(*p == 0 || *p == '\n') || p == s || (int64_t) lli != lli)
        return -1;
    *result = lli;
    return 0;
}

static int64_t
read_stat (const char *path)
{
    char str[64];
    int64_t r;
    int i;
    FILE *fp;

    fp = fopen (path, "r");
    if (!fp)
      return -1;

    /* read, but don't bail out before closing */
    i = fread (str, 1, sizeof str - 1, fp);

    if (fclose (fp) != 0        /* disk error */
        || i < 1)               /* ensure we read at least one byte */
        return -1;

    str[i] = '\0';              /* make sure the string is nul-terminated */
    if (xstrtoint64 (str, 10, &r) == -1)
        return -1;

    return r;
}

static int64_t
read_bd_stat (int device, int domid, const char *str)
{
    char path[PATH_MAX];
    int64_t r;

    snprintf (path, sizeof path,
              "/sys/devices/xen-backend/vbd-%d-%d/statistics/%s",
              domid, device, str);
    r = read_stat (path);
    if (r >= 0) return r;

    snprintf (path, sizeof path,
              "/sys/devices/xen-backend/tap-%d-%d/statistics/%s",
              domid, device, str);
    r = read_stat (path);
    return r;
}

/* In Xenstore, /local/domain/0/backend/vbd/<domid>/<device>/state,
 * if available, must be XenbusStateConnected (= 4), otherwise there
 * is no connected device.
 */
static int
check_bd_connected (xenUnifiedPrivatePtr priv, int device, int domid)
{
    char s[256], *rs;
    int r;
    unsigned len = 0;

    /* This code assumes we're connected if we can't get to
     * xenstore, etc.
     */
    if (!priv->xshandle) return 1;
    snprintf (s, sizeof s, "/local/domain/0/backend/vbd/%d/%d/state",
              domid, device);
    s[sizeof s - 1] = '\0';

    rs = xs_read (priv->xshandle, 0, s, &len);
    if (!rs) return 1;
    if (len == 0) {
        /* Hmmm ... we can get to xenstore but it returns an empty
         * string instead of an error.  Assume it's not connected
         * in this case.
         */
        free (rs);
        return 0;
    }

    r = STREQ (rs, "4");
    free (rs);
    return r;
}

static int
read_bd_stats (virConnectPtr conn, xenUnifiedPrivatePtr priv,
               int device, int domid, struct _virDomainBlockStats *stats)
{
    stats->rd_req   = read_bd_stat (device, domid, "rd_req");
    stats->rd_bytes = read_bd_stat (device, domid, "rd_sect");
    stats->wr_req   = read_bd_stat (device, domid, "wr_req");
    stats->wr_bytes = read_bd_stat (device, domid, "wr_sect");
    stats->errs     = read_bd_stat (device, domid, "oo_req");

    /* None of the files were found - it's likely that this version
     * of Xen is an old one which just doesn't support stats collection.
     */
    if (stats->rd_req == -1 && stats->rd_bytes == -1 &&
        stats->wr_req == -1 && stats->wr_bytes == -1 &&
        stats->errs == -1) {
        statsErrorFunc (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__,
                        "Failed to read any block statistics", domid);
        return -1;
    }

    /* If stats are all zero then either there really isn't any block
     * device activity, or there is no connected front end device
     * in which case there are no stats.
     */
    if (stats->rd_req == 0 && stats->rd_bytes == 0 &&
        stats->wr_req == 0 && stats->wr_bytes == 0 &&
        stats->errs == 0 &&
        !check_bd_connected (priv, device, domid)) {
        statsErrorFunc (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__,
                        "Frontend block device not connected", domid);
        return -1;
    }

    /* 'Bytes' was really sectors when we read it.  Scale up by
     * an assumed sector size.
     */
    if (stats->rd_bytes > 0) {
        if (stats->rd_bytes >= ((unsigned long long)1)<<(63-9)) {
            statsErrorFunc (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__,
                            "stats->rd_bytes would overflow 64 bit counter",
                            domid);
            return -1;
        }
        stats->rd_bytes *= 512;
    }
    if (stats->wr_bytes > 0) {
        if (stats->wr_bytes >= ((unsigned long long)1)<<(63-9)) {
            statsErrorFunc (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__,
                            "stats->wr_bytes would overflow 64 bit counter",
                            domid);
            return -1;
        }
        stats->wr_bytes *= 512;
    }

    return 0;
}

int
xenLinuxDomainBlockStats (xenUnifiedPrivatePtr priv,
                          virDomainPtr dom,
                          const char *path,
                          struct _virDomainBlockStats *stats)
{
    int minor, device;

    /* Paravirt domains:
     * Paths have the form "xvd[a-]" and map to paths
     * /sys/devices/xen-backend/(vbd|tap)-domid-major:minor/
     * statistics/(rd|wr|oo)_req.
     * The major:minor is in this case fixed as 202*256 + minor*16
     * where minor is 0 for xvda, 1 for xvdb and so on.
     *
     * XXX Not clear what happens to device numbers for devices
     * >= xdvo (minor >= 16), which would otherwise overflow the
     * 256 minor numbers assigned to this major number.  So we
     * currently limit you to the first 16 block devices per domain.
     */
    if (strlen (path) == 4 &&
        STREQLEN (path, "xvd", 3)) {
        if ((minor = path[3] - 'a') < 0 || minor >= 16) {
            statsErrorFunc (dom->conn, VIR_ERR_INVALID_ARG, __FUNCTION__,
                            "invalid path, should be xvda, xvdb, etc.",
                            dom->id);
            return -1;
        }
        device = XENVBD_MAJOR * 256 + minor * 16;

        return read_bd_stats (dom->conn, priv, device, dom->id, stats);
    }
    /* Fullvirt domains:
     * hda, hdb etc map to major = HD_MAJOR*256 + minor*16.
     *
     * See comment above about devices >= hdo.
     */
    else if (strlen (path) == 3 &&
             STREQLEN (path, "hd", 2)) {
        if ((minor = path[2] - 'a') < 0 || minor >= 16) {
            statsErrorFunc (dom->conn, VIR_ERR_INVALID_ARG, __FUNCTION__,
                            "invalid path, should be hda, hdb, etc.",
                            dom->id);
            return -1;
        }
        device = HD_MAJOR * 256 + minor * 16;

        return read_bd_stats (dom->conn, priv, device, dom->id, stats);
    }

    /* Otherwise, unsupported device name. */
    statsErrorFunc (dom->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__,
                    "unsupported path (use xvda, hda, etc.)", dom->id);
    return -1;
}

#endif /* WITH_XEN */

/*-------------------- interface stats --------------------*/
/* Just reads the named interface, so not Xen or QEMU-specific.
 * NB. Caller must check that libvirt user is trying to query
 * the interface of a domain they own.  We do no such checking.
 */

int
linuxDomainInterfaceStats (virConnectPtr conn, const char *path,
                           struct _virDomainInterfaceStats *stats)
{
    int path_len;
    FILE *fp;
    char line[256], *colon;

    fp = fopen ("/proc/net/dev", "r");
    if (!fp) {
        statsErrorFunc (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__,
                        "/proc/net/dev", errno);
        return -1;
    }

    path_len = strlen (path);

    while (fgets (line, sizeof line, fp)) {
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
            fclose (fp);

            return 0;
        }
    }
    fclose (fp);

    statsErrorFunc (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__,
                    "/proc/net/dev: Interface not found", 0);
    return -1;
}

#endif /* __linux__ */
/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
