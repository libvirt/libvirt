/*
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corporation
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *     Stefan Berger <stefanb@us.ibm.com>
 *
 * Notes:
 * netlink: http://lovezutto.googlepages.com/netlink.pdf
 *          iproute2 package
 *
 */

#include <config.h>

#if WITH_MACVTAP

# include <stdio.h>
# include <errno.h>
# include <fcntl.h>
# include <stdint.h>
# include <sys/socket.h>
# include <sys/ioctl.h>

# include <linux/if.h>
# include <linux/netlink.h>
# include <linux/rtnetlink.h>
# include <linux/if_tun.h>

# include "util.h"
# include "memory.h"
# include "macvtap.h"
# include "conf/domain_conf.h"
# include "virterror_internal.h"

# define VIR_FROM_THIS VIR_FROM_NET

# define macvtapError(code, ...)                                           \
        virReportErrorHelper(NULL, VIR_FROM_NET, code, __FILE__,           \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

# define MACVTAP_NAME_PREFIX	"macvtap"
# define MACVTAP_NAME_PATTERN	"macvtap%d"

static int nlOpen(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0)
        virReportSystemError(errno,
                             "%s",_("cannot open netlink socket"));
    return fd;
}


static void nlClose(int fd)
{
    close(fd);
}


/**
 * nlComm:
 * @nlmsg: pointer to netlink message
 * @respbuf: pointer to pointer where response buffer will be allocated
 * @respbuflen: pointer to integer holding the size of the response buffer
 *      on return of the function.
 *
 * Send the given message to the netlink layer and receive response.
 * Returns 0 on success, -1 on error. In case of error, no response
 * buffer will be returned.
 */
static
int nlComm(struct nlmsghdr *nlmsg,
           char **respbuf, int *respbuflen)
{
    int rc = 0;
    struct sockaddr_nl nladdr = {
            .nl_family = AF_NETLINK,
            .nl_pid    = 0,
            .nl_groups = 0,
    };
    int rcvChunkSize = 1024; // expecting less than that
    int rcvoffset = 0;
    ssize_t nbytes;
    int fd = nlOpen();

    if (fd < 0)
        return -1;

    nlmsg->nlmsg_flags |= NLM_F_ACK;

    nbytes = sendto(fd, (void *)nlmsg, nlmsg->nlmsg_len, 0,
                    (struct sockaddr *)&nladdr, sizeof(nladdr));
    if (nbytes < 0) {
        virReportSystemError(errno,
                             "%s", _("cannot send to netlink socket"));
        rc = -1;
        goto err_exit;
    }

    while (1) {
        if (VIR_REALLOC_N(*respbuf, rcvoffset+rcvChunkSize) < 0) {
            virReportOOMError();
            rc = -1;
            goto err_exit;
        }

        socklen_t addrlen = sizeof(nladdr);
        nbytes = recvfrom(fd, &((*respbuf)[rcvoffset]), rcvChunkSize, 0,
                          (struct sockaddr *)&nladdr, &addrlen);
        if (nbytes < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            virReportSystemError(errno, "%s",
                                 _("error receiving from netlink socket"));
            rc = -1;
            goto err_exit;
        }
        rcvoffset += nbytes;
        break;
    }
    *respbuflen = rcvoffset;

err_exit:
    if (rc == -1) {
        VIR_FREE(*respbuf);
        *respbuf = NULL;
        *respbuflen = 0;
    }

    nlClose(fd);
    return rc;
}


static struct rtattr *
rtattrCreate(char *buffer, int bufsize, int type,
             const void *data, int datalen)
{
    struct rtattr *r = (struct rtattr *)buffer;
    r->rta_type = type;
    r->rta_len  = RTA_LENGTH(datalen);
    if (r->rta_len > bufsize)
        return NULL;
    memcpy(RTA_DATA(r), data, datalen);
    return r;
}


static void
nlInit(struct nlmsghdr *nlm, int flags, int type)
{
    nlm->nlmsg_len = NLMSG_LENGTH(0);
    nlm->nlmsg_flags = flags;
    nlm->nlmsg_type = type;
}


static void
nlAlign(struct nlmsghdr *nlm)
{
    nlm->nlmsg_len = NLMSG_ALIGN(nlm->nlmsg_len);
}


static void *
nlAppend(struct nlmsghdr *nlm, int totlen, const void *data, int datalen)
{
    char *pos;
    nlAlign(nlm);
    if (nlm->nlmsg_len + NLMSG_ALIGN(datalen) > totlen)
        return NULL;
    pos = (char *)nlm + nlm->nlmsg_len;
    memcpy(pos, data, datalen);
    nlm->nlmsg_len += datalen;
    nlAlign(nlm);
    return pos;
}


static int
getIfIndex(bool reportError,
           const char *ifname,
           int *idx)
{
    int rc = 0;
    struct ifreq ifreq;
    int fd = socket(PF_PACKET, SOCK_DGRAM, 0);

    if (fd < 0)
        return errno;

    if (virStrncpy(ifreq.ifr_name, ifname, strlen(ifname),
                   sizeof(ifreq.ifr_name)) == NULL) {
        if (reportError)
            macvtapError(VIR_ERR_INTERNAL_ERROR,
                         _("invalid interface name %s"),
                         ifname);
        rc = EINVAL;
        goto err_exit;
    }
    if (ioctl(fd, SIOCGIFINDEX, &ifreq) >= 0)
        *idx = ifreq.ifr_ifindex;
    else {
        if (reportError)
            macvtapError(VIR_ERR_INTERNAL_ERROR,
                         _("interface %s does not exist"),
                         ifname);
        rc = ENODEV;
    }

err_exit:
    close(fd);

    return rc;
}


/*
 * chgIfFlags: Change flags on an interface
 * @ifname : name of the interface
 * @flagclear : the flags to clear
 * @flagset : the flags to set
 *
 * The new flags of the interface will be calculated as
 * flagmask = (~0 ^ flagclear)
 * newflags = (curflags & flagmask) | flagset;
 *
 * Returns 0 on success, errno on failure.
 */
static int chgIfFlags(const char *ifname, short flagclear, short flagset) {
    struct ifreq ifr;
    int rc = 0;
    int flags;
    short flagmask = (~0 ^ flagclear);
    int fd = socket(PF_PACKET, SOCK_DGRAM, 0);

    if (fd < 0)
        return errno;

    if (virStrncpy(ifr.ifr_name,
                   ifname, strlen(ifname), sizeof(ifr.ifr_name)) == NULL) {
        rc = ENODEV;
        goto err_exit;
    }

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        rc = errno;
        goto err_exit;
    }

    flags = (ifr.ifr_flags & flagmask) | flagset;

    if (ifr.ifr_flags != flags) {
        ifr.ifr_flags = flags;

        if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
            rc = errno;
    }

err_exit:
    close(fd);
    return rc;
}

/*
 * ifUp
 * @name: name of the interface
 * @up: 1 for up, 0 for down
 *
 * Function to control if an interface is activated (up, 1) or not (down, 0)
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
static int
ifUp(const char *name, int up)
{
    return chgIfFlags(name,
                      (up) ? 0      : IFF_UP,
                      (up) ? IFF_UP : 0);
}


static int
link_add(const char *type,
         const unsigned char *macaddress, int macaddrsize,
         const char *ifname,
         const char *srcdev,
         uint32_t macvlan_mode,
         int *retry)
{
    int rc = 0;
    char nlmsgbuf[256];
    struct nlmsghdr *nlm = (struct nlmsghdr *)nlmsgbuf, *resp;
    struct nlmsgerr *err;
    char rtattbuf[64];
    struct rtattr *rta, *rta1, *li;
    struct ifinfomsg i = { .ifi_family = AF_UNSPEC };
    int ifindex;
    char *recvbuf = NULL;
    int recvbuflen;

    if (getIfIndex(true, srcdev, &ifindex) != 0)
        return -1;

    *retry = 0;

    memset(&nlmsgbuf, 0, sizeof(nlmsgbuf));

    nlInit(nlm, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL, RTM_NEWLINK);

    if (!nlAppend(nlm, sizeof(nlmsgbuf), &i, sizeof(i)))
        goto buffer_too_small;

    rta = rtattrCreate(rtattbuf, sizeof(rtattbuf), IFLA_LINK,
                       &ifindex, sizeof(ifindex));
    if (!rta)
        goto buffer_too_small;

    if (!nlAppend(nlm, sizeof(nlmsgbuf), rtattbuf, rta->rta_len))
        goto buffer_too_small;

    rta = rtattrCreate(rtattbuf, sizeof(rtattbuf), IFLA_ADDRESS,
                       macaddress, macaddrsize);
    if (!rta)
        goto buffer_too_small;

    if (!nlAppend(nlm, sizeof(nlmsgbuf), rtattbuf, rta->rta_len))
        goto buffer_too_small;

    if (ifname) {
        rta = rtattrCreate(rtattbuf, sizeof(rtattbuf), IFLA_IFNAME,
                           ifname, strlen(ifname) + 1);
        if (!rta)
            goto buffer_too_small;

        if (!nlAppend(nlm, sizeof(nlmsgbuf), rtattbuf, rta->rta_len))
            goto buffer_too_small;
    }

    rta = rtattrCreate(rtattbuf, sizeof(rtattbuf), IFLA_LINKINFO, NULL, 0);
    if (!rta)
        goto buffer_too_small;

    if (!(li = nlAppend(nlm, sizeof(nlmsgbuf), rtattbuf, rta->rta_len)))
        goto buffer_too_small;

    rta = rtattrCreate(rtattbuf, sizeof(rtattbuf), IFLA_INFO_KIND,
                       type, strlen(type));
    if (!rta)
        goto buffer_too_small;

    if (!nlAppend(nlm, sizeof(nlmsgbuf), rtattbuf, rta->rta_len))
        goto buffer_too_small;

    if (macvlan_mode > 0) {
        rta = rtattrCreate(rtattbuf, sizeof(rtattbuf), IFLA_INFO_DATA,
                           NULL, 0);
        if (!rta)
            goto buffer_too_small;

        if (!(rta1 = nlAppend(nlm, sizeof(nlmsgbuf), rtattbuf, rta->rta_len)))
            goto buffer_too_small;

        rta = rtattrCreate(rtattbuf, sizeof(rtattbuf), IFLA_MACVLAN_MODE,
                           &macvlan_mode, sizeof(macvlan_mode));
        if (!rta)
            goto buffer_too_small;

        if (!nlAppend(nlm, sizeof(nlmsgbuf), rtattbuf, rta->rta_len))
            goto buffer_too_small;

        rta1->rta_len = (char *)nlm + nlm->nlmsg_len - (char *)rta1;
    }

    li->rta_len = (char *)nlm + nlm->nlmsg_len - (char *)li;

    if (nlComm(nlm, &recvbuf, &recvbuflen) < 0)
        return -1;

    if (recvbuflen < NLMSG_LENGTH(0) || recvbuf == NULL)
        goto malformed_resp;

    resp = (struct nlmsghdr *)recvbuf;

    switch (resp->nlmsg_type) {
    case NLMSG_ERROR:
        err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (resp->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
            goto malformed_resp;

        switch (-err->error) {

        case 0:
        break;

        case EEXIST:
            *retry = 1;
            rc = -1;
        break;

        default:
            virReportSystemError(-err->error,
                                 _("error creating %s type of interface"),
                                 type);
            rc = -1;
        }
    break;

    case NLMSG_DONE:
    break;

    default:
        goto malformed_resp;
    }

    VIR_FREE(recvbuf);

    return rc;

malformed_resp:
    macvtapError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("malformed netlink response message"));
    VIR_FREE(recvbuf);
    return -1;

buffer_too_small:
    macvtapError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("internal buffer is too small"));
    return -1;
}


static int
link_del(const char *name)
{
    int rc = 0;
    char nlmsgbuf[256];
    struct nlmsghdr *nlm = (struct nlmsghdr *)nlmsgbuf, *resp;
    struct nlmsgerr *err;
    char rtattbuf[64];
    struct rtattr *rta;
    struct ifinfomsg ifinfo = { .ifi_family = AF_UNSPEC };
    char *recvbuf = NULL;
    int recvbuflen;

    memset(&nlmsgbuf, 0, sizeof(nlmsgbuf));

    nlInit(nlm, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL, RTM_DELLINK);

    if (!nlAppend(nlm, sizeof(nlmsgbuf), &ifinfo, sizeof(ifinfo)))
        goto buffer_too_small;

    rta = rtattrCreate(rtattbuf, sizeof(rtattbuf), IFLA_IFNAME,
                       name, strlen(name)+1);
    if (!rta)
        goto buffer_too_small;

    if (!nlAppend(nlm, sizeof(nlmsgbuf), rtattbuf, rta->rta_len))
        goto buffer_too_small;

    if (nlComm(nlm, &recvbuf, &recvbuflen) < 0)
        return -1;

    if (recvbuflen < NLMSG_LENGTH(0) || recvbuf == NULL)
        goto malformed_resp;

    resp = (struct nlmsghdr *)recvbuf;

    switch (resp->nlmsg_type) {
    case NLMSG_ERROR:
        err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (resp->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
            goto malformed_resp;

        switch (-err->error) {
        case 0:
        break;

        default:
            virReportSystemError(-err->error,
                                 _("error destroying %s interface"),
                                 name);
            rc = -1;
        }
    break;

    case NLMSG_DONE:
    break;

    default:
        goto malformed_resp;
    }

    VIR_FREE(recvbuf);

    return rc;

malformed_resp:
    macvtapError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("malformed netlink response message"));
    VIR_FREE(recvbuf);
    return -1;

buffer_too_small:
    macvtapError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("internal buffer is too small"));
    return -1;
}


/* Open the macvtap's tap device.
 * @ifname: Name of the macvtap interface
 * @retries : Number of retries in case udev for example may need to be
 *            waited for to create the tap chardev
 * Returns negative value in case of error, the file descriptor otherwise.
 */
static
int openTap(const char *ifname,
            int retries)
{
    FILE *file;
    char path[64];
    int ifindex;
    char tapname[50];
    int tapfd;

    if (snprintf(path, sizeof(path),
                 "/sys/class/net/%s/ifindex", ifname) >= sizeof(path)) {
        virReportSystemError(errno,
                             "%s",
                             _("buffer for ifindex path is too small"));
        return -1;
    }

    file = fopen(path, "r");

    if (!file) {
        virReportSystemError(errno,
                             _("cannot open macvtap file %s to determine "
                               "interface index"), path);
        return -1;
    }

    if (fscanf(file, "%d", &ifindex) != 1) {
        virReportSystemError(errno,
                             "%s",_("cannot determine macvtap's tap device "
                             "interface index"));
        fclose(file);
        return -1;
    }

    fclose(file);

    if (snprintf(tapname, sizeof(tapname),
                 "/dev/tap%d", ifindex) >= sizeof(tapname)) {
        virReportSystemError(errno,
                             "%s",
                             _("internal buffer for tap device is too small"));
        return -1;
    }

    while (1) {
        // may need to wait for udev to be done
        tapfd = open(tapname, O_RDWR);
        if (tapfd < 0 && retries > 0) {
            retries--;
            usleep(20000);
            continue;
        }
        break;
    }

    if (tapfd < 0)
        virReportSystemError(errno,
                             _("cannot open macvtap tap device %s"),
                             tapname);

    return tapfd;
}


static uint32_t
macvtapModeFromInt(enum virDomainNetdevMacvtapType mode)
{
    switch (mode) {
    case VIR_DOMAIN_NETDEV_MACVTAP_MODE_PRIVATE:
        return MACVLAN_MODE_PRIVATE;
    break;

    case VIR_DOMAIN_NETDEV_MACVTAP_MODE_BRIDGE:
        return MACVLAN_MODE_BRIDGE;
    break;

    case VIR_DOMAIN_NETDEV_MACVTAP_MODE_VEPA:
    default:
        return MACVLAN_MODE_VEPA;
    }
}


/**
 * configMacvtapTap:
 * @tapfd: file descriptor of the macvtap tap
 * @vnet_hdr: 1 to enable IFF_VNET_HDR, 0 to disable it
 *
 * Returns 0 on success, -1 in case of fatal error, error code otherwise.
 *
 * Turn the IFF_VNET_HDR flag, if requested and available, make sure
 * it's off in the other cases.
 * A fatal error is defined as the VNET_HDR flag being set but it cannot
 * be turned off for some reason. This is reported with -1. Other fatal
 * error is not being able to read the interface flags. In that case the
 * macvtap device should not be used.
 */
static int
configMacvtapTap(int tapfd, int vnet_hdr)
{
    unsigned int features;
    struct ifreq ifreq;
    short new_flags = 0;
    int rc_on_fail = 0;
    const char *errmsg = NULL;

    memset(&ifreq, 0, sizeof(ifreq));

    if (ioctl(tapfd, TUNGETIFF, &ifreq) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot get interface flags on macvtap tap"));
        return -1;
    }

    new_flags = ifreq.ifr_flags;

    if ((ifreq.ifr_flags & IFF_VNET_HDR) && !vnet_hdr) {
        new_flags = ifreq.ifr_flags & ~IFF_VNET_HDR;
        rc_on_fail = -1;
        errmsg = _("cannot clean IFF_VNET_HDR flag on macvtap tap");
    } else if ((ifreq.ifr_flags & IFF_VNET_HDR) == 0 && vnet_hdr) {
        if (ioctl(tapfd, TUNGETFEATURES, &features) != 0)
            return errno;
        if ((features & IFF_VNET_HDR)) {
            new_flags = ifreq.ifr_flags | IFF_VNET_HDR;
            errmsg = _("cannot set IFF_VNET_HDR flag on macvtap tap");
        }
    }

    if (new_flags != ifreq.ifr_flags) {
        ifreq.ifr_flags = new_flags;
        if (ioctl(tapfd, TUNSETIFF, &ifreq) < 0) {
            virReportSystemError(errno, "%s", errmsg);
            return rc_on_fail;
        }
    }

    return 0;
}


/**
 * openMacvtapTap:
 * Create an instance of a macvtap device and open its tap character
 * device.
 * @tgifname: Interface name that the macvtap is supposed to have. May
 *    be NULL if this function is supposed to choose a name
 * @macaddress: The MAC address for the macvtap device
 * @linkdev: The interface name of the NIC to connect to the external bridge
 * @mode_str: String describing the mode. Valid are 'bridge', 'vepa' and
 *     'private'.
 * @res_ifname: Pointer to a string pointer where the actual name of the
 *     interface will be stored into if everything succeeded. It is up
 *     to the caller to free the string.
 *
 * Returns file descriptor of the tap device in case of success,
 * negative value otherwise with error reported.
 *
 */
int
openMacvtapTap(const char *tgifname,
               const unsigned char *macaddress,
               const char *linkdev,
               int mode,
               char **res_ifname,
               int vnet_hdr)
{
    const char *type = "macvtap";
    int c, rc;
    char ifname[IFNAMSIZ];
    int retries, do_retry = 0;
    uint32_t macvtapMode = macvtapModeFromInt(mode);
    const char *cr_ifname;
    int ifindex;

    *res_ifname = NULL;

    if (tgifname) {
        if(getIfIndex(false, tgifname, &ifindex) == 0) {
            if (STRPREFIX(tgifname,
                          MACVTAP_NAME_PREFIX)) {
                goto create_name;
            }
            virReportSystemError(errno,
                                 _("Interface %s already exists"), tgifname);
            return -1;
        }
        cr_ifname = tgifname;
        rc = link_add(type, macaddress, 6, tgifname, linkdev,
                      macvtapMode, &do_retry);
        if (rc)
            return -1;
    } else {
create_name:
        retries = 5;
        for (c = 0; c < 8192; c++) {
            snprintf(ifname, sizeof(ifname), MACVTAP_NAME_PATTERN, c);
            if (getIfIndex(false, ifname, &ifindex) == ENODEV) {
                rc = link_add(type, macaddress, 6, ifname, linkdev,
                              macvtapMode, &do_retry);
                if (rc == 0)
                    break;

                if (do_retry && --retries)
                    continue;
                return -1;
            }
        }
        cr_ifname = ifname;
    }

    rc = ifUp(cr_ifname, 1);
    if (rc != 0) {
        virReportSystemError(errno,
                             _("cannot 'up' interface %s -- another "
                             "macvtap device may be 'up' and have the same "
                             "MAC address"),
                             cr_ifname);
        rc = -1;
        goto link_del_exit;
    }

    rc = openTap(cr_ifname, 10);

    if (rc >= 0) {
        if (configMacvtapTap(rc, vnet_hdr) < 0) {
            close(rc);
            rc = -1;
            goto link_del_exit;
        }
        *res_ifname = strdup(cr_ifname);
    } else
        goto link_del_exit;

    return rc;

link_del_exit:
    link_del(cr_ifname);

    return rc;
}


/**
 * delMacvtapByName:
 * @ifname : The name of the macvtap interface
 *
 * Delete an interface given its name.
 */
void
delMacvtap(const char *ifname)
{
    link_del(ifname);
}

#endif
