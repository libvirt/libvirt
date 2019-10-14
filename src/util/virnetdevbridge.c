/*
 * Copyright (C) 2007-2015 Red Hat, Inc.
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

#include "virnetdevbridge.h"
#include "virnetdev.h"
#include "virerror.h"
#include "virutil.h"
#include "virfile.h"
#include "viralloc.h"
#include "virlog.h"
#include "intprops.h"
#include "virstring.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#ifdef __linux__
# if defined(HAVE_LIBNL)
#  include "virnetlink.h"
# endif
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

VIR_LOG_INIT("util.netdevbridge");

#if defined(HAVE_BSD_BRIDGE_MGMT)
static int virNetDevBridgeCmd(const char *brname,
                              u_long op,
                              void *arg,
                              size_t argsize)
{
    struct ifdrv ifd;
    VIR_AUTOCLOSE s = -1;

    memset(&ifd, 0, sizeof(ifd));

    if ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot open network interface control socket"));
        return -1;
    }

    if (virStrcpyStatic(ifd.ifd_name, brname) < 0) {
       virReportSystemError(ERANGE,
                            _("Network interface name '%s' is too long"),
                            brname);
       return -1;
    }

    ifd.ifd_cmd = op;
    ifd.ifd_len = argsize;
    ifd.ifd_data = arg;

    return ioctl(s, SIOCSDRVSPEC, &ifd);
}
#endif

#if defined(HAVE_STRUCT_IFREQ) && defined(__linux__)
/*
 * Bridge parameters can be set via sysfs on newish kernels,
 * or by  ioctl on older kernels. Perhaps we could just use
 * ioctl for every kernel, but its not clear what the long
 * term lifespan of the ioctl interface is...
 * Fall back to ioctl if sysfs interface is not available or
 * failing (e.g. due to container isolation).
 */
static int virNetDevBridgeSet(const char *brname,
                              const char *paramname,  /* sysfs param name */
                              unsigned long value,    /* new value */
                              int fd,                 /* control socket */
                              struct ifreq *ifr)      /* pre-filled bridge name */
{
    VIR_AUTOFREE(char *) path = NULL;

    if (virAsprintf(&path, SYSFS_NET_DIR "%s/bridge/%s", brname, paramname) < 0)
        return -1;

    if (virFileExists(path)) {
        char valuestr[INT_BUFSIZE_BOUND(value)];
        snprintf(valuestr, sizeof(valuestr), "%lu", value);
        if (virFileWriteStr(path, valuestr, 0) >= 0)
            return 0;
        VIR_DEBUG("Unable to set bridge %s %s via sysfs", brname, paramname);
    }

    unsigned long paramid;
    if (STREQ(paramname, "stp_state")) {
        paramid = BRCTL_SET_BRIDGE_STP_STATE;
    } else if (STREQ(paramname, "forward_delay")) {
        paramid = BRCTL_SET_BRIDGE_FORWARD_DELAY;
    } else {
        virReportSystemError(EINVAL,
                             _("Unable to set bridge %s %s via ioctl"),
                             brname, paramname);
        return -1;
    }
    unsigned long args[] = { paramid, value, 0, 0 };
    ifr->ifr_data = (char*)&args;
    if (ioctl(fd, SIOCDEVPRIVATE, ifr) < 0) {
        virReportSystemError(errno,
                             _("Failed to set bridge %s %s via ioctl"),
                             brname, paramname);
        return -1;
    }

    return 0;
}


static int virNetDevBridgeGet(const char *brname,
                              const char *paramname,  /* sysfs param name */
                              unsigned long *value)   /* current value */
{
    struct ifreq ifr;
    VIR_AUTOFREE(char *) path = NULL;
    VIR_AUTOCLOSE fd = -1;

    if (virAsprintf(&path, SYSFS_NET_DIR "%s/bridge/%s", brname, paramname) < 0)
        return -1;

    if (virFileExists(path)) {
        VIR_AUTOFREE(char *) valuestr = NULL;

        if (virFileReadAll(path, INT_BUFSIZE_BOUND(unsigned long),
                           &valuestr) < 0)
            return -1;

        if (virStrToLong_ul(valuestr, NULL, 10, value) < 0) {
            virReportSystemError(EINVAL,
                                 _("Unable to get bridge %s %s"),
                                 brname, paramname);
            return -1;
        }
    } else {
        struct __bridge_info info;
        unsigned long args[] = { BRCTL_GET_BRIDGE_INFO, (unsigned long)&info, 0, 0 };

        if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
            return -1;

        ifr.ifr_data = (char*)&args;
        if (ioctl(fd, SIOCDEVPRIVATE, ifr) < 0) {
            virReportSystemError(errno,
                                 _("Unable to get bridge %s %s"), brname, paramname);
            return -1;
        }

        if (STREQ(paramname, "stp_state")) {
            *value = info.stp_enabled;
        } else if (STREQ(paramname, "forward_delay")) {
            *value = info.forward_delay;
        } else {
            virReportSystemError(EINVAL,
                                 _("Unable to get bridge %s %s"), brname, paramname);
            return -1;
        }
    }

    return 0;
}
#endif /* __linux__ */

#if defined(__linux__)
static int
virNetDevBridgePortSet(const char *brname,
                       const char *ifname,
                       const char *paramname,
                       unsigned long value)
{
    char valuestr[INT_BUFSIZE_BOUND(value)];
    int ret = -1;
    VIR_AUTOFREE(char *) path = NULL;

    snprintf(valuestr, sizeof(valuestr), "%lu", value);

    if (virAsprintf(&path, SYSFS_NET_DIR "%s/brif/%s/%s",
                    brname, ifname, paramname) < 0)
        return -1;

    if (!virFileExists(path))
        errno = EINVAL;
    else
        ret = virFileWriteStr(path, valuestr, 0);

    if (ret < 0) {
        virReportSystemError(errno,
                             _("Unable to set bridge %s port %s %s to %s"),
                             brname, ifname, paramname, valuestr);
    }

    return ret;
}


static int
virNetDevBridgePortGet(const char *brname,
                       const char *ifname,
                       const char *paramname,
                       unsigned long *value)
{
    VIR_AUTOFREE(char *) path = NULL;
    VIR_AUTOFREE(char *) valuestr = NULL;

    if (virAsprintf(&path, SYSFS_NET_DIR "%s/brif/%s/%s",
                    brname, ifname, paramname) < 0)
        return -1;

    if (virFileReadAll(path, INT_BUFSIZE_BOUND(unsigned long), &valuestr) < 0)
        return -1;

    if (virStrToLong_ul(valuestr, NULL, 10, value) < 0) {
        virReportSystemError(EINVAL,
                             _("Unable to get bridge %s port %s %s"),
                             brname, ifname, paramname);
        return -1;
    }

    return 0;
}


int
virNetDevBridgePortGetLearning(const char *brname,
                               const char *ifname,
                               bool *enable)
{
    int ret = -1;
    unsigned long value;

    if (virNetDevBridgePortGet(brname, ifname, "learning", &value) < 0)
       goto cleanup;

    *enable = !!value;
    ret = 0;
 cleanup:
    return ret;
}


int
virNetDevBridgePortSetLearning(const char *brname,
                               const char *ifname,
                               bool enable)
{
    return virNetDevBridgePortSet(brname, ifname, "learning", enable ? 1 : 0);
}


int
virNetDevBridgePortGetUnicastFlood(const char *brname,
                                   const char *ifname,
                                   bool *enable)
{
    int ret = -1;
    unsigned long value;

    if (virNetDevBridgePortGet(brname, ifname, "unicast_flood", &value) < 0)
       goto cleanup;

    *enable = !!value;
    ret = 0;
 cleanup:
    return ret;
}


int
virNetDevBridgePortSetUnicastFlood(const char *brname,
                                   const char *ifname,
                                   bool enable)
{
    return virNetDevBridgePortSet(brname, ifname, "unicast_flood", enable ? 1 : 0);
}


#else
int
virNetDevBridgePortGetLearning(const char *brname G_GNUC_UNUSED,
                               const char *ifname G_GNUC_UNUSED,
                               bool *enable G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get bridge port learning on this platform"));
    return -1;
}


int
virNetDevBridgePortSetLearning(const char *brname G_GNUC_UNUSED,
                               const char *ifname G_GNUC_UNUSED,
                               bool enable G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to set bridge port learning on this platform"));
    return -1;
}


int
virNetDevBridgePortGetUnicastFlood(const char *brname G_GNUC_UNUSED,
                                   const char *ifname G_GNUC_UNUSED,
                                   bool *enable G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get bridge port unicast_flood on this platform"));
    return -1;
}


int
virNetDevBridgePortSetUnicastFlood(const char *brname G_GNUC_UNUSED,
                                   const char *ifname G_GNUC_UNUSED,
                                   bool enable G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to set bridge port unicast_flood on this platform"));
    return -1;
}
#endif


/**
 * virNetDevBridgeCreate:
 * @brname: the bridge name
 *
 * This function register a new bridge
 *
 * Returns 0 in case of success or -1 on failure
 */
#if defined(HAVE_STRUCT_IFREQ) && defined(SIOCBRADDBR)
static int
virNetDevBridgeCreateWithIoctl(const char *brname)
{
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(NULL, NULL)) < 0)
        return -1;

    if (ioctl(fd, SIOCBRADDBR, brname) < 0) {
        virReportSystemError(errno,
                             _("Unable to create bridge %s"), brname);
        return -1;
    }

    return 0;
}
#endif

#if defined(__linux__) && defined(HAVE_LIBNL)
int
virNetDevBridgeCreate(const char *brname)
{
    /* use a netlink RTM_NEWLINK message to create the bridge */
    int error = 0;

    if (virNetlinkNewLink(brname, "bridge", NULL, &error) < 0) {
# if defined(HAVE_STRUCT_IFREQ) && defined(SIOCBRADDBR)
        if (error == -EOPNOTSUPP) {
            /* fallback to ioctl if netlink doesn't support creating bridges */
            return virNetDevBridgeCreateWithIoctl(brname);
        }
# endif
        if (error < 0)
            virReportSystemError(-error, _("error creating bridge interface %s"),
                                 brname);

        return -1;
    }

    return 0;
}


#elif defined(HAVE_STRUCT_IFREQ) && defined(SIOCBRADDBR)
int
virNetDevBridgeCreate(const char *brname)
{
    return virNetDevBridgeCreateWithIoctl(brname);
}


#elif defined(HAVE_STRUCT_IFREQ) && defined(SIOCIFCREATE2)
int
virNetDevBridgeCreate(const char *brname)
{
    struct ifreq ifr;
    VIR_AUTOCLOSE s = -1;

    if ((s = virNetDevSetupControl("bridge", &ifr)) < 0)
        return -1;

    if (ioctl(s, SIOCIFCREATE2, &ifr) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create bridge device"));
        return -1;
    }

    if (virNetDevSetName(ifr.ifr_name, brname) == -1)
        return -1;

    return 0;
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
static int
virNetDevBridgeDeleteWithIoctl(const char *brname)
{
    VIR_AUTOCLOSE fd = -1;

    ignore_value(virNetDevSetOnline(brname, false));

    if ((fd = virNetDevSetupControl(NULL, NULL)) < 0)
        return -1;

    if (ioctl(fd, SIOCBRDELBR, brname) < 0) {
        virReportSystemError(errno,
                             _("Unable to delete bridge %s"), brname);
        return -1;
    }

    return 0;
}
#endif


#if defined(__linux__) && defined(HAVE_LIBNL)
int
virNetDevBridgeDelete(const char *brname)
{
    /* If netlink is available, use it, as it is successful at
     * deleting a bridge even if it is currently IFF_UP. fallback to
     * using ioctl(SIOCBRDELBR) if netlink fails with EOPNOTSUPP.
     */
# if defined(HAVE_STRUCT_IFREQ) && defined(SIOCBRDELBR)
    return virNetlinkDelLink(brname, virNetDevBridgeDeleteWithIoctl);
# else
    return virNetlinkDelLink(brname, NULL);
# endif
}


#elif defined(HAVE_STRUCT_IFREQ) && defined(SIOCBRDELBR)
int
virNetDevBridgeDelete(const char *brname)
{
    return virNetDevBridgeDeleteWithIoctl(brname);
}


#elif defined(HAVE_STRUCT_IFREQ) && defined(SIOCIFDESTROY)
int
virNetDevBridgeDelete(const char *brname)
{
    struct ifreq ifr;
    VIR_AUTOCLOSE s = -1;

    if ((s = virNetDevSetupControl(brname, &ifr)) < 0)
        return -1;

    if (ioctl(s, SIOCIFDESTROY, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to remove bridge %s"),
                             brname);
        return -1;
    }

    return 0;
}
#else
int virNetDevBridgeDelete(const char *brname G_GNUC_UNUSED)
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
    struct ifreq ifr;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        return -1;

    if (!(ifr.ifr_ifindex = if_nametoindex(ifname))) {
        virReportSystemError(ENODEV,
                             _("Unable to get interface index for %s"), ifname);
        return -1;
    }

    if (ioctl(fd, SIOCBRADDIF, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to add bridge %s port %s"), brname, ifname);
        return -1;
    }

    return 0;
}
#elif defined(HAVE_BSD_BRIDGE_MGMT)
int virNetDevBridgeAddPort(const char *brname,
                           const char *ifname)
{
    struct ifbreq req;

    memset(&req, 0, sizeof(req));
    if (virStrcpyStatic(req.ifbr_ifsname, ifname) < 0) {
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
    struct ifreq ifr;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        return -1;

    if (!(ifr.ifr_ifindex = if_nametoindex(ifname))) {
        virReportSystemError(ENODEV,
                             _("Unable to get interface index for %s"), ifname);

        return -1;
    }

    if (ioctl(fd, SIOCBRDELIF, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to remove bridge %s port %s"), brname, ifname);
        return -1;
    }

    return 0;
}
#elif defined(HAVE_BSD_BRIDGE_MGMT)
int virNetDevBridgeRemovePort(const char *brname,
                              const char *ifname)
{
    struct ifbreq req;

    memset(&req, 0, sizeof(req));
    if (virStrcpyStatic(req.ifbr_ifsname, ifname) < 0) {
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
    struct ifreq ifr;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        return -1;

    return virNetDevBridgeSet(brname, "forward_delay", MS_TO_JIFFIES(delay),
                              fd, &ifr);
}


/**
 * virNetDevBridgeGetSTPDelay:
 * @brname: the bridge device name
 * @delayms: the forward delay in milliseconds
 *
 * Retrieves the forward delay for the bridge device @brname
 * storing it in @delayms. The forward delay is only meaningful
 * if STP is enabled
 *
 * Returns 0 on success, -1 on error+
 */
int virNetDevBridgeGetSTPDelay(const char *brname,
                               int *delayms)
{
    int ret = -1;
    unsigned long val = 0;

    ret = virNetDevBridgeGet(brname, "forward_delay", &val);
    *delayms = JIFFIES_TO_MS(val);

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
    struct ifreq ifr;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        return -1;

    return virNetDevBridgeSet(brname, "stp_state", enable ? 1 : 0,
                              fd, &ifr);
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
    int ret = -1;
    unsigned long val = 0;

    ret = virNetDevBridgeGet(brname, "stp_state", &val);
    *enabled = val ? true : false;

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
                               int *delay G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to get STP delay on %s on this platform"),
                         brname);
    return -1;
}

int virNetDevBridgeSetSTP(const char *brname G_GNUC_UNUSED,
                          bool enable G_GNUC_UNUSED)

{
    /* FreeBSD doesn't allow to set STP per bridge,
     * only per-device in bridge */
    return 0;
}
int virNetDevBridgeGetSTP(const char *brname,
                          bool *enable G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to get STP on %s on this platform"),
                         brname);
    return -1;
}
#else
int virNetDevBridgeSetSTPDelay(const char *brname,
                               int delay G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to set STP delay on %s on this platform"),
                         brname);
    return -1;
}
int virNetDevBridgeGetSTPDelay(const char *brname,
                               int *delay G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to get STP delay on %s on this platform"),
                         brname);
    return -1;
}

int virNetDevBridgeSetSTP(const char *brname,
                          bool enable G_GNUC_UNUSED)

{
    virReportSystemError(ENOSYS,
                         _("Unable to set STP on %s on this platform"),
                         brname);
    return -1;
}
int virNetDevBridgeGetSTP(const char *brname,
                          bool *enable G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to get STP on %s on this platform"),
                         brname);
    return -1;
}
#endif

#if defined(HAVE_STRUCT_IFREQ) && defined(__linux__)
/**
 * virNetDevBridgeGetVlanFiltering:
 * @brname: the bridge device name
 * @enable: true or false
 *
 * Retrieves the vlan_filtering setting for the bridge device @brname
 * storing it in @enable.
 *
 * Returns 0 on success, -1 on error
 */
int
virNetDevBridgeGetVlanFiltering(const char *brname,
                                bool *enable)
{
    int ret = -1;
    unsigned long value;

    if (virNetDevBridgeGet(brname, "vlan_filtering", &value) < 0)
        goto cleanup;

    *enable = !!value;
    ret = 0;
 cleanup:
    return ret;
}


/**
 * virNetDevBridgeSetVlanFiltering:
 * @brname: the bridge name
 * @enable: true or false
 *
 * Set the bridge vlan_filtering mode
 *
 * Returns 0 in case of success or -1 on failure
 */

int
virNetDevBridgeSetVlanFiltering(const char *brname,
                                bool enable)
{
    return virNetDevBridgeSet(brname, "vlan_filtering", enable ? 1 : 0, -1, NULL);
}


#else
int
virNetDevBridgeGetVlanFiltering(const char *brname G_GNUC_UNUSED,
                                bool *enable G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get bridge vlan_filtering on this platform"));
    return -1;
}


int
virNetDevBridgeSetVlanFiltering(const char *brname G_GNUC_UNUSED,
                                bool enable G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to set bridge vlan_filtering on this platform"));
    return -1;
}
#endif


#if defined(__linux__) && defined(HAVE_LIBNL)

# ifndef NTF_SELF
#  define NTF_SELF 0x02
# endif

# ifndef NTF_MASTER
#  define NTF_MASTER 0x04
# endif

/* virNetDevBridgeFDBAddDel:
 * @mac: the MAC address being added to the table
 * @ifname: name of the port (interface) of the bridge that wants this MAC
 * @flags: any of virNetDevBridgeFDBFlags ORed together.
 * @isAdd: true if adding the entry, fals if deleting
 *
 * Use netlink RTM_NEWNEIGH and RTM_DELNEIGH messages to add and
 * delete entries from a bridge's fdb. The bridge itself is not
 * referenced in the arguments to the function, only the name of the
 * device that is attached to the bridge (since a device can only be
 * attached to one bridge at a time, and must be attached for this
 * function to make sense, the kernel easily infers which bridge's fdb
 * is being modified by looking at the device name/index).
 *
 * Attempting to add an existing entry, or delete a non-existing entry
 * *is* an error.
 *
 * returns 0 on success, -1 on failure.
 */
static int
virNetDevBridgeFDBAddDel(const virMacAddr *mac, const char *ifname,
                         unsigned int flags, bool isAdd)
{
    struct nlmsgerr *err;
    unsigned int recvbuflen;
    struct ndmsg ndm = { .ndm_family = PF_BRIDGE, .ndm_state = NUD_NOARP };
    VIR_AUTOPTR(virNetlinkMsg) nl_msg = NULL;
    VIR_AUTOFREE(struct nlmsghdr *) resp = NULL;

    if (virNetDevGetIndex(ifname, &ndm.ndm_ifindex) < 0)
        return -1;

    if (flags & VIR_NETDEVBRIDGE_FDB_FLAG_ROUTER)
        ndm.ndm_flags |= NTF_ROUTER;
    if (flags & VIR_NETDEVBRIDGE_FDB_FLAG_SELF)
        ndm.ndm_flags |= NTF_SELF;
    if (flags & VIR_NETDEVBRIDGE_FDB_FLAG_MASTER)
        ndm.ndm_flags |= NTF_MASTER;
    /* default self (same as iproute2's bridge command */
    if (!(ndm.ndm_flags & (NTF_MASTER | NTF_SELF)))
        ndm.ndm_flags |= NTF_SELF;

    if (flags & VIR_NETDEVBRIDGE_FDB_FLAG_PERMANENT)
        ndm.ndm_state |= NUD_PERMANENT;
    if (flags & VIR_NETDEVBRIDGE_FDB_FLAG_TEMP)
        ndm.ndm_state |= NUD_REACHABLE;
    /* default permanent, same as iproute2's bridge command */
    if (!(ndm.ndm_state & (NUD_PERMANENT | NUD_REACHABLE)))
        ndm.ndm_state |= NUD_PERMANENT;

    nl_msg = nlmsg_alloc_simple(isAdd ? RTM_NEWNEIGH : RTM_DELNEIGH,
                                NLM_F_REQUEST |
                                (isAdd ? (NLM_F_CREATE | NLM_F_EXCL) : 0));
    if (!nl_msg) {
        virReportOOMError();
        return -1;
    }

    if (nlmsg_append(nl_msg, &ndm, sizeof(ndm), NLMSG_ALIGNTO) < 0)
        goto buffer_too_small;
    if (nla_put(nl_msg, NDA_LLADDR, VIR_MAC_BUFLEN, mac) < 0)
        goto buffer_too_small;

    /* NB: this message can also accept a Destination IP, a port, a
     * vlan tag, and a via (see iproute2/bridge/fdb.c:fdb_modify()),
     * but those aren't required for our application
     */

    if (virNetlinkCommand(nl_msg, &resp, &recvbuflen, 0, 0,
                          NETLINK_ROUTE, 0) < 0) {
        return -1;
    }
    if (recvbuflen < NLMSG_LENGTH(0) || resp == NULL)
        goto malformed_resp;

    switch (resp->nlmsg_type) {
    case NLMSG_ERROR:
        err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (resp->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
            goto malformed_resp;
        if (err->error) {
            virReportSystemError(-err->error,
                                 _("error adding fdb entry for %s"), ifname);
            return -1;
        }
        break;
    case NLMSG_DONE:
        break;

    default:
        goto malformed_resp;
    }

    return 0;

 malformed_resp:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("malformed netlink response message"));
    return -1;

 buffer_too_small:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("allocated netlink buffer is too small"));
    return -1;
}


#else
static int
virNetDevBridgeFDBAddDel(const virMacAddr *mac G_GNUC_UNUSED,
                         const char *ifname G_GNUC_UNUSED,
                         unsigned int fdbFlags G_GNUC_UNUSED,
                         bool isAdd G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to add/delete fdb entries on this platform"));
    return -1;
}


#endif

int
virNetDevBridgeFDBAdd(const virMacAddr *mac, const char *ifname,
                      unsigned int flags)
{
    return virNetDevBridgeFDBAddDel(mac, ifname, flags, true);
}


int
virNetDevBridgeFDBDel(const virMacAddr *mac, const char *ifname,
                      unsigned int flags)
{
    return virNetDevBridgeFDBAddDel(mac, ifname, flags, false);
}
