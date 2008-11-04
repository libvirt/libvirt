/*
 * Linux block and network stats.
 *
 * Copyright (C) 2007, 2008 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Richard W.M. Jones <rjones@redhat.com>
 */

#include <config.h>

/* This file only applies on Linux. */
#ifdef __linux__

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>

#ifdef WITH_XEN
#include <xs.h>
#endif

#include "virterror_internal.h"
#include "datatypes.h"
#include "util.h"
#include "xen_unified.h"
#include "stats_linux.h"
#include "memory.h"

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

    errmsg = virErrorMsg(error, info);
    if (func != NULL) {
        snprintf(fullinfo, sizeof (fullinfo) - 1, "%s: %s", func, info);
        fullinfo[sizeof (fullinfo) - 1] = 0;
        info = fullinfo;
    }
    virRaiseError(conn, NULL, NULL, VIR_FROM_STATS_LINUX, error,
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
        statsErrorFunc (conn, VIR_ERR_INTERNAL_ERROR, __FUNCTION__,
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
        statsErrorFunc (conn, VIR_ERR_INTERNAL_ERROR, __FUNCTION__,
                        "Frontend block device not connected", domid);
        return -1;
    }

    /* 'Bytes' was really sectors when we read it.  Scale up by
     * an assumed sector size.
     */
    if (stats->rd_bytes > 0) {
        if (stats->rd_bytes >= ((unsigned long long)1)<<(63-9)) {
            statsErrorFunc (conn, VIR_ERR_INTERNAL_ERROR, __FUNCTION__,
                            "stats->rd_bytes would overflow 64 bit counter",
                            domid);
            return -1;
        }
        stats->rd_bytes *= 512;
    }
    if (stats->wr_bytes > 0) {
        if (stats->wr_bytes >= ((unsigned long long)1)<<(63-9)) {
            statsErrorFunc (conn, VIR_ERR_INTERNAL_ERROR, __FUNCTION__,
                            "stats->wr_bytes would overflow 64 bit counter",
                            domid);
            return -1;
        }
        stats->wr_bytes *= 512;
    }

    return 0;
}

static int
disk_re_match(const char *regex, const char *path, int *part)
{
    regex_t myreg;
    int err;
    int retval;
    regmatch_t pmatch[3];

    retval = 0;

    err = regcomp(&myreg, regex, REG_EXTENDED);
    if (err != 0)
        return 0;

    err = regexec(&myreg, path, 3, pmatch, 0);

    if (err == 0) {
        /* OK, we have a match; see if we have a partition */
        *part = 0;
        retval = 1;
        if (pmatch[1].rm_so != -1) {
            if (virStrToLong_i(path + pmatch[1].rm_so, NULL, 10, part) < 0)
                retval = 0;
        }
    }

    regfree(&myreg);

    return retval;
}

int
xenLinuxDomainDeviceID(virConnectPtr conn, int domid, const char *path)
{
    int major, minor;
    int part;
    int retval;
    char *mod_path;

    int const scsi_majors[] = { SCSI_DISK0_MAJOR, SCSI_DISK1_MAJOR,
                                SCSI_DISK2_MAJOR, SCSI_DISK3_MAJOR,
                                SCSI_DISK4_MAJOR, SCSI_DISK5_MAJOR,
                                SCSI_DISK6_MAJOR, SCSI_DISK7_MAJOR,
                                SCSI_DISK8_MAJOR, SCSI_DISK9_MAJOR,
                                SCSI_DISK10_MAJOR, SCSI_DISK11_MAJOR,
                                SCSI_DISK12_MAJOR, SCSI_DISK13_MAJOR,
                                SCSI_DISK14_MAJOR, SCSI_DISK15_MAJOR };
    int const ide_majors[] = { IDE0_MAJOR, IDE1_MAJOR, IDE2_MAJOR, IDE3_MAJOR,
                               IDE4_MAJOR, IDE5_MAJOR, IDE6_MAJOR, IDE7_MAJOR,
                               IDE8_MAJOR, IDE9_MAJOR };

    /*
     * Possible block device majors & partition ranges. This
     * matches the ranges supported in Xend xen/util/blkif.py
     *
     * hdNM:  N=a-t, M=1-63, major={IDE0_MAJOR -> IDE9_MAJOR}
     * sdNM:  N=a-z,aa-iv, M=1-15, major={SCSI_DISK0_MAJOR -> SCSI_DISK15_MAJOR}
     * xvdNM: N=a-p M=1-15, major=XENVBD_MAJOR
     * xvdNM: N=q-z,aa-iz M=1-15, major=(1<<28)
     *
     * The path for statistics will be
     *
     * /sys/devices/xen-backend/(vbd|tap)-{domid}-{devid}/statistics/{...}
     */

    if (strlen(path) >= 5 && STRPREFIX(path, "/dev/"))
        retval = asprintf(&mod_path, "%s", path);
    else
        retval = asprintf(&mod_path, "/dev/%s", path);

    if (retval < 0) {
        statsErrorFunc (conn, VIR_ERR_NO_MEMORY, __FUNCTION__,
                        "allocating mod_path", domid);
        return -1;
    }

    retval = -1;

    if (disk_re_match("/dev/sd[a-z]([1-9]|1[0-5])?$", mod_path, &part)) {
        major = scsi_majors[(mod_path[7] - 'a') / 16];
        minor = ((mod_path[7] - 'a') % 16) * 16 + part;
        retval = major * 256 + minor;
    }
    else if (disk_re_match("/dev/sd[a-h][a-z]([1-9]|1[0-5])?$",
                           mod_path, &part) ||
             disk_re_match("/dev/sdi[a-v]([1-9]|1[0-5])?$",
                           mod_path, &part)) {
        major = scsi_majors[((mod_path[7] - 'a' + 1) * 26 + (mod_path[8] - 'a')) / 16];
        minor = (((mod_path[7] - 'a' + 1) * 26 + (mod_path[8] - 'a')) % 16)
            * 16 + part;
        retval = major * 256 + minor;
    }
    else if (disk_re_match("/dev/hd[a-t]([1-9]|[1-5][0-9]|6[0-3])?$",
                           mod_path, &part)) {
        major = ide_majors[(mod_path[7] - 'a') / 2];
        minor = ((mod_path[7] - 'a') % 2) * 64 + part;
        retval = major * 256 + minor;
    }
    else if (disk_re_match("/dev/xvd[a-p]([1-9]|1[0-5])?$", mod_path, &part))
        retval = (202 << 8) + ((mod_path[8] - 'a') << 4) + part;
    else if (disk_re_match("/dev/xvd[q-z]([1-9]|1[0-5])?$", mod_path, &part))
        retval = (1 << 28) + ((mod_path[8] - 'a') << 8) + part;
    else if (disk_re_match("/dev/xvd[a-i][a-z]([1-9]|1[0-5])?$",
                           mod_path, &part))
        retval = (1 << 28) + (((mod_path[8] - 'a' + 1) * 26 + (mod_path[9] - 'a')) << 8) + part;
    /*
     * OK, we've now checked the common case (things that work); check the
     * beginning of the strings for better error messages
     */
    else if (strlen(mod_path) >= 7 && STRPREFIX(mod_path, "/dev/sd"))
        statsErrorFunc (conn, VIR_ERR_INVALID_ARG, __FUNCTION__,
                        "invalid path, device names must be in the range sda[1-15] - sdiv[1-15]",
                        domid);
    else if (strlen(mod_path) >= 7 && STRPREFIX(mod_path, "/dev/hd"))
        statsErrorFunc (conn, VIR_ERR_INVALID_ARG, __FUNCTION__,
                        "invalid path, device names must be in the range hda[1-63] - hdt[1-63]",
                        domid);
    else if (strlen(mod_path) >= 8 && STRPREFIX(mod_path, "/dev/xvd"))
        statsErrorFunc (conn, VIR_ERR_INVALID_ARG, __FUNCTION__,
                        "invalid path, device names must be in the range xvda[1-15] - xvdiz[1-15]",
                        domid);
    else
        statsErrorFunc (conn, VIR_ERR_INVALID_ARG, __FUNCTION__,
                        "unsupported path, use xvdN, hdN, or sdN", domid);

    VIR_FREE(mod_path);

    return retval;
}

int
xenLinuxDomainBlockStats (xenUnifiedPrivatePtr priv,
                          virDomainPtr dom,
                          const char *path,
                          struct _virDomainBlockStats *stats)
{
    int device = xenLinuxDomainDeviceID(dom->conn, dom->id, path);

    if (device < 0)
        return -1;

    return read_bd_stats (dom->conn, priv, device, dom->id, stats);
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
        statsErrorFunc (conn, VIR_ERR_INTERNAL_ERROR, __FUNCTION__,
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

    statsErrorFunc (conn, VIR_ERR_INTERNAL_ERROR, __FUNCTION__,
                    "/proc/net/dev: Interface not found", 0);
    return -1;
}

#endif /* __linux__ */
