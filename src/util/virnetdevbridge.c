/*
 * Copyright (C) 2007-2013 Red Hat, Inc.
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
 * Authors:
 *     Mark McLoughlin <markmc@redhat.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virnetdevbridge.h"
#include "virnetdev.h"
#include "virerror.h"
#include "virutil.h"
#include "virfile.h"
#include "viralloc.h"
#include "intprops.h"
#include "virstring.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#ifdef __linux__
# include <linux/sockios.h>
# include <linux/param.h>     /* HZ                 */
# if NETINET_LINUX_WORKAROUND
/* Depending on the version of kernel vs. glibc, there may be a collision
 * between <net/in.h> and kernel IPv6 structures.  The different types
 * are ABI compatible, but choke the C type system; work around it by
 * using temporary redefinitions.  */
#  define in6_addr in6_addr_
#  define sockaddr_in6 sockaddr_in6_
#  define ipv6_mreq ipv6_mreq_
#  define in6addr_any in6addr_any_
#  define in6addr_loopback in6addr_loopback_
# endif
# include <linux/in6.h>
# include <linux/if_bridge.h> /* SYSFS_BRIDGE_ATTR  */
# if NETINET_LINUX_WORKAROUND
#  undef in6_addr
#  undef sockaddr_in6
#  undef ipv6_mreq
#  undef in6addr_any
#  undef in6addr_loopback
# endif

# define JIFFIES_TO_MS(j) (((j)*1000)/HZ)
# define MS_TO_JIFFIES(ms) (((ms)*HZ)/1000)
#endif

#if defined(HAVE_BSD_BRIDGE_MGMT)
# include <net/ethernet.h>
# include <net/if_bridgevar.h>
#endif

#define VIR_FROM_THIS VIR_FROM_NONE


#if defined(HAVE_BSD_BRIDGE_MGMT)
static int virNetDevBridgeCmd(const char *brname,
                              u_long op,
                              void *arg,
                              size_t argsize)
{
    int s;
    int ret = -1;
    struct ifdrv ifd;

    memset(&ifd, 0, sizeof(ifd));

    if ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot open network interface control socket"));
        return -1;
    }

    if (virStrcpyStatic(ifd.ifd_name, brname) == NULL) {
       virReportSystemError(ERANGE,
                            _("Network interface name '%s' is too long"),
                            brname);
       goto cleanup;
    }

    ifd.ifd_cmd = op;
    ifd.ifd_len = argsize;
    ifd.ifd_data = arg;

    ret = ioctl(s, SIOCSDRVSPEC, &ifd);

 cleanup:
    VIR_FORCE_CLOSE(s);

    return ret;
}
#endif

#if defined(HAVE_STRUCT_IFREQ) && defined(__linux__)
# define SYSFS_NET_DIR "/sys/class/net"
/*
 * Bridge parameters can be set via sysfs on newish kernels,
 * or by  ioctl on older kernels. Perhaps we could just use
 * ioctl for every kernel, but its not clear what the long
 * term lifespan of the ioctl interface is...
 */
static int virNetDevBridgeSet(const char *brname,
                              const char *paramname,  /* sysfs param name */
                              unsigned long value,    /* new value */
                              int fd,                 /* control socket */
                              struct ifreq *ifr)      /* pre-filled bridge name */
{
    char *path = NULL;
    int ret = -1;

    if (virAsprintf(&path, "%s/%s/bridge/%s", SYSFS_NET_DIR, brname, paramname) < 0)
        return -1;

    if (virFileExists(path)) {
        char valuestr[INT_BUFSIZE_BOUND(value)];
        snprintf(valuestr, sizeof(valuestr), "%lu", value);
        if (virFileWriteStr(path, valuestr, 0) < 0) {
            virReportSystemError(errno,
                                 _("Unable to set bridge %s %s"), brname, paramname);
            goto cleanup;
        }
    } else {
        unsigned long paramid;
        if (STREQ(paramname, "stp_state")) {
            paramid = BRCTL_SET_BRIDGE_STP_STATE;
        } else if (STREQ(paramname, "forward_delay")) {
            paramid = BRCTL_SET_BRIDGE_FORWARD_DELAY;
        } else {
            virReportSystemError(EINVAL,
                                 _("Unable to set bridge %s %s"), brname, paramname);
            goto cleanup;
        }
        unsigned long args[] = { paramid, value, 0, 0 };
        ifr->ifr_data = (char*)&args;
        if (ioctl(fd, SIOCDEVPRIVATE, ifr) < 0) {
            virReportSystemError(errno,
                                 _("Unable to set bridge %s %s"), brname, paramname);
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(path);
    return ret;
}


static int virNetDevBridgeGet(const char *brname,
                              const char *paramname,  /* sysfs param name */
                              unsigned long *value,   /* current value */
                              int fd,                 /* control socket */
                              struct ifreq *ifr)      /* pre-filled bridge name */
{
    char *path = NULL;
    int ret = -1;

    if (virAsprintf(&path, "%s/%s/bridge/%s", SYSFS_NET_DIR, brname, paramname) < 0)
        return -1;

    if (virFileExists(path)) {
        char *valuestr;
        if (virFileReadAll(path, INT_BUFSIZE_BOUND(unsigned long),
                           &valuestr) < 0)
            goto cleanup;

        if (virStrToLong_ul(valuestr, NULL, 10, value) < 0) {
            virReportSystemError(EINVAL,
                                 _("Unable to get bridge %s %s"),
                                 brname, paramname);
            VIR_FREE(valuestr);
            goto cleanup;
        }
        VIR_FREE(valuestr);
    } else {
        struct __bridge_info info;
        unsigned long args[] = { BRCTL_GET_BRIDGE_INFO, (unsigned long)&info, 0, 0 };
        ifr->ifr_data = (char*)&args;
        if (ioctl(fd, SIOCDEVPRIVATE, ifr) < 0) {
            virReportSystemError(errno,
                                 _("Unable to get bridge %s %s"), brname, paramname);
            goto cleanup;
        }

        if (STREQ(paramname, "stp_state")) {
            *value = info.stp_enabled;
        } else if (STREQ(paramname, "forward_delay")) {
            *value = info.forward_delay;
        } else {
            virReportSystemError(EINVAL,
                                 _("Unable to get bridge %s %s"), brname, paramname);
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(path);
    return ret;
}
#endif /* __linux__ */


/**
 * virNetDevBridgeCreate:
 * @brname: the bridge name
 *
 * This function register a new bridge
 *
 * Returns 0 in case of success or -1 on failure
 */
#if defined(HAVE_STRUCT_IFREQ) && defined(SIOCBRADDBR)
int virNetDevBridgeCreate(const char *brname)
{
    int fd = -1;
    int ret = -1;

    if ((fd = virNetDevSetupControl(NULL, NULL)) < 0)
        return -1;

    if (ioctl(fd, SIOCBRADDBR, brname) < 0) {
        virReportSystemError(errno,
                             _("Unable to create bridge %s"), brname);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#elif defined(HAVE_STRUCT_IFREQ) && defined(SIOCIFCREATE2)
int virNetDevBridgeCreate(const char *brname)
{
    int s;
    struct ifreq ifr;
    int ret = - 1;

    if ((s = virNetDevSetupControl("bridge", &ifr)) < 0)
        return -1;

    if (ioctl(s, SIOCIFCREATE2, &ifr) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create bridge device"));
        goto cleanup;
    }

    if (virNetDevSetName(ifr.ifr_name, brname) == -1) {
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(s);
    return ret;
}
#else
int virNetDevBridgeCreate(const char *brname)
{
    virReportSystemError(ENOSYS,
                         _("Unable to create bridge %s"), brname);
    return -1;
}
#endif

/**
 * virNetDevBridgeDelete:
 * @brname: the bridge name
 *
 * Remove a bridge from the layer.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
#if defined(HAVE_STRUCT_IFREQ) && defined(SIOCBRDELBR)
int virNetDevBridgeDelete(const char *brname)
{
    int fd = -1;
    int ret = -1;

    if ((fd = virNetDevSetupControl(NULL, NULL)) < 0)
        return -1;

    if (ioctl(fd, SIOCBRDELBR, brname) < 0) {
        virReportSystemError(errno,
                             _("Unable to delete bridge %s"), brname);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#elif defined(HAVE_STRUCT_IFREQ) && defined(SIOCIFDESTROY)
int virNetDevBridgeDelete(const char *brname)
{
    int s;
    struct ifreq ifr;
    int ret = -1;

    if ((s = virNetDevSetupControl(brname, &ifr)) < 0)
        return -1;

    if (ioctl(s, SIOCIFDESTROY, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to remove bridge %s"),
                             brname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(s);
    return ret;
}
#else
int virNetDevBridgeDelete(const char *brname ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to delete bridge %s"), brname);
    return EINVAL;
}
#endif

/**
 * virNetDevBridgeAddPort:
 * @brname: the bridge name
 * @ifname: the network interface name
 *
 * Adds an interface to a bridge
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
#if defined(HAVE_STRUCT_IFREQ) && defined(SIOCBRADDIF)
int virNetDevBridgeAddPort(const char *brname,
                           const char *ifname)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        return -1;

    if (!(ifr.ifr_ifindex = if_nametoindex(ifname))) {
        virReportSystemError(ENODEV,
                             _("Unable to get interface index for %s"), ifname);
        goto cleanup;
    }

    if (ioctl(fd, SIOCBRADDIF, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to add bridge %s port %s"), brname, ifname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#elif defined(HAVE_BSD_BRIDGE_MGMT)
int virNetDevBridgeAddPort(const char *brname,
                           const char *ifname)
{
    struct ifbreq req;

    memset(&req, 0, sizeof(req));
    if (virStrcpyStatic(req.ifbr_ifsname, ifname) == NULL) {
        virReportSystemError(ERANGE,
                             _("Network interface name '%s' is too long"),
                             ifname);
        return -1;
    }

    if (virNetDevBridgeCmd(brname, BRDGADD, &req, sizeof(req)) < 0) {
        virReportSystemError(errno,
                             _("Unable to add bridge %s port %s"), brname, ifname);
        return -1;
    }

    return 0;
}
#else
int virNetDevBridgeAddPort(const char *brname,
                           const char *ifname)
{
    virReportSystemError(ENOSYS,
                         _("Unable to add bridge %s port %s"), brname, ifname);
    return -1;
}
#endif

/**
 * virNetDevBridgeRemovePort:
 * @brname: the bridge name
 * @ifname: the network interface name
 *
 * Removes an interface from a bridge
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
#if defined(HAVE_STRUCT_IFREQ) && defined(SIOCBRDELIF)
int virNetDevBridgeRemovePort(const char *brname,
                              const char *ifname)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        return -1;

    if (!(ifr.ifr_ifindex = if_nametoindex(ifname))) {
        virReportSystemError(ENODEV,
                             _("Unable to get interface index for %s"), ifname);

        goto cleanup;
    }

    if (ioctl(fd, SIOCBRDELIF, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to remove bridge %s port %s"), brname, ifname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#elif defined(HAVE_BSD_BRIDGE_MGMT)
int virNetDevBridgeRemovePort(const char *brname,
                           const char *ifname)
{
    struct ifbreq req;

    memset(&req, 0, sizeof(req));
    if (virStrcpyStatic(req.ifbr_ifsname, ifname) == NULL) {
        virReportSystemError(ERANGE,
                             _("Network interface name '%s' is too long"),
                             ifname);
        return -1;
    }

    if (virNetDevBridgeCmd(brname, BRDGDEL, &req, sizeof(req)) < 0) {
        virReportSystemError(errno,
                             _("Unable to remove bridge %s port %s"), brname, ifname);
       return -1;
    }

    return 0;
}
#else
int virNetDevBridgeRemovePort(const char *brname,
                              const char *ifname)
{
    virReportSystemError(ENOSYS,
                         _("Unable to remove bridge %s port %s"), brname, ifname);
    return -1;
}
#endif


#if defined(HAVE_STRUCT_IFREQ) && defined(__linux__)
/**
 * virNetDevBridgeSetSTPDelay:
 * @brname: the bridge name
 * @delay: delay in milliseconds
 *
 * Set the bridge forward delay
 *
 * Returns 0 in case of success or -1 on failure
 */

int virNetDevBridgeSetSTPDelay(const char *brname,
                               int delay)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        goto cleanup;

    ret = virNetDevBridgeSet(brname, "forward_delay", MS_TO_JIFFIES(delay),
                             fd, &ifr);

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}


/**
 * virNetDevBridgeGetSTPDelay:
 * @brname: the bridge device name
 * @delayms: the forward delay in milliseconds
 *
 * Retrives the forward delay for the bridge device @brname
 * storing it in @delayms. The forward delay is only meaningful
 * if STP is enabled
 *
 * Returns 0 on success, -1 on error+
 */
int virNetDevBridgeGetSTPDelay(const char *brname,
                               int *delayms)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;
    unsigned long val;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        goto cleanup;

    ret = virNetDevBridgeGet(brname, "forward_delay", &val,
                             fd, &ifr);
    *delayms = JIFFIES_TO_MS(val);

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}


/**
 * virNetDevBridgeSetSTP:
 * @brname: the bridge name
 * @enable: 1 to enable, 0 to disable
 *
 * Control whether the bridge participates in the spanning tree protocol,
 * in general don't disable it without good reasons.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevBridgeSetSTP(const char *brname,
                          bool enable)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        goto cleanup;

    ret = virNetDevBridgeSet(brname, "stp_state", enable ? 1 : 0,
                             fd, &ifr);

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}


/**
 * virNetDevBridgeGetSTP:
 * @brname: the bridge device name
 * @enabled: returns the STP state
 *
 * Determine the state of the spanning tree protocol on
 * the device @brname, returning the state in @enabled
 *
 * Returns 0 on success, -1 on error
 */
int virNetDevBridgeGetSTP(const char *brname,
                          bool *enabled)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;
    unsigned long val;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        goto cleanup;

    ret = virNetDevBridgeGet(brname, "stp_state", &val,
                             fd, &ifr);
    *enabled = val ? true : false;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#elif defined(HAVE_BSD_BRIDGE_MGMT)
int virNetDevBridgeSetSTPDelay(const char *brname,
                               int delay)
{
    struct ifbrparam param;
    u_long delay_seconds = delay / 1000;

    /* FreeBSD doesn't allow setting STP delay < 4 */
    delay_seconds = delay_seconds < 4 ? 4 : delay_seconds;
    param.ifbrp_fwddelay = delay_seconds & 0xff;

    if (virNetDevBridgeCmd(brname, BRDGSFD, &param, sizeof(param)) < 0) {
        virReportSystemError(errno,
                             _("Unable to set STP delay on %s"), brname);
        return -1;
    }

    return 0;
}
int virNetDevBridgeGetSTPDelay(const char *brname,
                               int *delay ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to get STP delay on %s on this platform"),
                         brname);
    return -1;
}

int virNetDevBridgeSetSTP(const char *brname ATTRIBUTE_UNUSED,
                          bool enable ATTRIBUTE_UNUSED)

{
    /* FreeBSD doesn't allow to set STP per bridge,
     * only per-device in bridge */
    return 0;
}
int virNetDevBridgeGetSTP(const char *brname,
                          bool *enable ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to get STP on %s on this platform"),
                         brname);
    return -1;
}
#else
int virNetDevBridgeSetSTPDelay(const char *brname,
                               int delay ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to set STP delay on %s on this platform"),
                         brname);
    return -1;
}
int virNetDevBridgeGetSTPDelay(const char *brname,
                               int *delay ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to get STP delay on %s on this platform"),
                         brname);
    return -1;
}

int virNetDevBridgeSetSTP(const char *brname,
                          bool enable ATTRIBUTE_UNUSED)

{
    virReportSystemError(ENOSYS,
                         _("Unable to set STP on %s on this platform"),
                         brname);
    return -1;
}
int virNetDevBridgeGetSTP(const char *brname,
                          bool *enable ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to get STP on %s on this platform"),
                         brname);
    return -1;
}
#endif
