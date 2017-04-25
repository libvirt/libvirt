/*
 * Copyright (C) 2010-2017 Red Hat, Inc.
 * Copyright (C) 2010-2012 IBM Corporation
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
 *     Stefan Berger <stefanb@us.ibm.com>
 *
 * Notes:
 * netlink: http://lovezutto.googlepages.com/netlink.pdf
 *          iproute2 package
 *
 */

#include <config.h>

#include "virnetdevmacvlan.h"
#include "virmacaddr.h"
#include "virerror.h"
#include "virthread.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NET

VIR_ENUM_IMPL(virNetDevMacVLanMode, VIR_NETDEV_MACVLAN_MODE_LAST,
              "vepa",
              "private",
              "bridge",
              "passthrough")

#if WITH_MACVTAP
# include <stdint.h>
# include <stdio.h>
# include <errno.h>
# include <fcntl.h>
# include <sys/socket.h>
# include <sys/ioctl.h>

# include <net/if.h>
# include <linux/if_tun.h>

/* Older kernels lacked this enum value.  */
# if !HAVE_DECL_MACVLAN_MODE_PASSTHRU
#  define MACVLAN_MODE_PASSTHRU 8
# endif

# include "viralloc.h"
# include "virlog.h"
# include "viruuid.h"
# include "virfile.h"
# include "virnetlink.h"
# include "virnetdev.h"
# include "virpidfile.h"
# include "virbitmap.h"

VIR_LOG_INIT("util.netdevmacvlan");

# define VIR_NET_GENERATED_MACVTAP_PATTERN VIR_NET_GENERATED_MACVTAP_PREFIX "%d"
# define VIR_NET_GENERATED_MACVLAN_PATTERN VIR_NET_GENERATED_MACVLAN_PREFIX "%d"
# define VIR_NET_GENERATED_PREFIX \
    ((flags & VIR_NETDEV_MACVLAN_CREATE_WITH_TAP) ? \
     VIR_NET_GENERATED_MACVTAP_PREFIX : VIR_NET_GENERATED_MACVLAN_PREFIX)

# define MACVLAN_MAX_ID 8191

virMutex virNetDevMacVLanCreateMutex = VIR_MUTEX_INITIALIZER;
virBitmapPtr macvtapIDs = NULL;
virBitmapPtr macvlanIDs = NULL;

static int
virNetDevMacVLanOnceInit(void)
{

    if (!macvtapIDs &&
        !(macvtapIDs = virBitmapNew(MACVLAN_MAX_ID + 1)))
        return -1;
    if (!macvlanIDs &&
        !(macvlanIDs = virBitmapNew(MACVLAN_MAX_ID + 1)))
        return -1;
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetDevMacVLan);


/**
 * virNetDevMacVLanReserveID:
 *
 *  @id: id 0 - MACVLAN_MAX_ID+1 to reserve (or -1 for "first free")
 *  @flags: set VIR_NETDEV_MACVLAN_CREATE_WITH_TAP for macvtapN else macvlanN
 *  @quietFail: don't log an error if this name is already in-use
 *  @nextFree: reserve the next free ID *after* @id rather than @id itself
 *
 *  Reserve the indicated ID in the appropriate bitmap, or find the
 *  first free ID if @id is -1.
 *
 *  Returns newly reserved ID# on success, or -1 to indicate failure.
 */
static int
virNetDevMacVLanReserveID(int id, unsigned int flags,
                          bool quietFail, bool nextFree)
{
    virBitmapPtr bitmap;

    if (virNetDevMacVLanInitialize() < 0)
       return -1;

    bitmap = (flags & VIR_NETDEV_MACVLAN_CREATE_WITH_TAP) ?
        macvtapIDs :  macvlanIDs;

    if (id > MACVLAN_MAX_ID) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("can't use name %s%d - out of range 0-%d"),
                       VIR_NET_GENERATED_PREFIX, id, MACVLAN_MAX_ID);
        return -1;
    }

    if ((id < 0 || nextFree) &&
        (id = virBitmapNextClearBit(bitmap, id)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no unused %s names available"),
                       VIR_NET_GENERATED_PREFIX);
        return -1;
    }

    if (virBitmapIsBitSet(bitmap, id)) {
        if (quietFail) {
            VIR_INFO("couldn't reserve name %s%d - already in use",
                     VIR_NET_GENERATED_PREFIX, id);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("couldn't reserve name %s%d - already in use"),
                           VIR_NET_GENERATED_PREFIX, id);
        }
        return -1;
    }

    if (virBitmapSetBit(bitmap, id) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("couldn't mark %s%d as used"),
                       VIR_NET_GENERATED_PREFIX, id);
        return -1;
    }

    VIR_INFO("reserving device %s%d", VIR_NET_GENERATED_PREFIX, id);
    return id;
}


/**
 * virNetDevMacVLanReleaseID:
 *  @id: id 0 - MACVLAN_MAX_ID+1 to release
 *
 *  Returns 0 for success or -1 for failure.
 */
static int
virNetDevMacVLanReleaseID(int id, unsigned int flags)
{
    virBitmapPtr bitmap;

    if (virNetDevMacVLanInitialize() < 0)
        return 0;

    bitmap = (flags & VIR_NETDEV_MACVLAN_CREATE_WITH_TAP) ?
        macvtapIDs :  macvlanIDs;

    if (id > MACVLAN_MAX_ID) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("can't free name %s%d - out of range 0-%d"),
                       VIR_NET_GENERATED_PREFIX, id, MACVLAN_MAX_ID);
        return -1;
    }

    if (id < 0)
        return 0;

    VIR_INFO("releasing %sdevice %s%d",
             virBitmapIsBitSet(bitmap, id) ? "" : "unreserved",
             VIR_NET_GENERATED_PREFIX, id);

    if (virBitmapClearBit(bitmap, id) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("couldn't mark %s%d as unused"),
                       VIR_NET_GENERATED_PREFIX, id);
        return -1;
    }
    return 0;
}


/**
 * virNetDevMacVLanReserveName:
 *
 *  @name: already-known name of device
 *  @quietFail: don't log an error if this name is already in-use
 *
 *  Extract the device type and id from a macvtap/macvlan device name
 *  and mark the appropriate position as in-use in the appropriate
 *  bitmap.
 *
 *  Returns reserved ID# on success, -1 on failure, -2 if the name
 *  doesn't fit the auto-pattern (so not reserveable).
 */
int
virNetDevMacVLanReserveName(const char *name, bool quietFail)
{
    unsigned int id;
    unsigned int flags = 0;
    const char *idstr = NULL;

    if (virNetDevMacVLanInitialize() < 0)
       return -1;

    if (STRPREFIX(name, VIR_NET_GENERATED_MACVTAP_PREFIX)) {
        idstr = name + strlen(VIR_NET_GENERATED_MACVTAP_PREFIX);
        flags |= VIR_NETDEV_MACVLAN_CREATE_WITH_TAP;
    } else if (STRPREFIX(name, VIR_NET_GENERATED_MACVLAN_PREFIX)) {
        idstr = name + strlen(VIR_NET_GENERATED_MACVLAN_PREFIX);
    } else {
        return -2;
    }

    if (virStrToLong_ui(idstr, NULL, 10, &id) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("couldn't get id value from macvtap device name %s"),
                       name);
        return -1;
    }
    return virNetDevMacVLanReserveID(id, flags, quietFail, false);
}


/**
 * virNetDevMacVLanReleaseName:
 *
 *  @name: already-known name of device
 *
 *  Extract the device type and id from a macvtap/macvlan device name
 *  and mark the appropriate position as in-use in the appropriate
 *  bitmap.
 *
 *  returns 0 on success, -1 on failure
 */
int
virNetDevMacVLanReleaseName(const char *name)
{
    unsigned int id;
    unsigned int flags = 0;
    const char *idstr = NULL;

    if (virNetDevMacVLanInitialize() < 0)
       return -1;

    if (STRPREFIX(name, VIR_NET_GENERATED_MACVTAP_PREFIX)) {
        idstr = name + strlen(VIR_NET_GENERATED_MACVTAP_PREFIX);
        flags |= VIR_NETDEV_MACVLAN_CREATE_WITH_TAP;
    } else if (STRPREFIX(name, VIR_NET_GENERATED_MACVLAN_PREFIX)) {
        idstr = name + strlen(VIR_NET_GENERATED_MACVLAN_PREFIX);
    } else {
        return 0;
    }

    if (virStrToLong_ui(idstr, NULL, 10, &id) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("couldn't get id value from macvtap device name %s"),
                       name);
        return -1;
    }
    return virNetDevMacVLanReleaseID(id, flags);
}


/**
 * virNetDevMacVLanCreate:
 *
 * @ifname: The name the interface is supposed to have; optional parameter
 * @type: The type of device, i.e., "macvtap", "macvlan"
 * @macaddress: The MAC address of the device
 * @srcdev: The name of the 'link' device
 * @macvlan_mode: The macvlan mode to use
 * @retry: Pointer to integer that will be '1' upon return if an interface
 *         with the same name already exists and it is worth to try
 *         again with a different name
 *
 * Create a macvtap device with the given properties.
 *
 * Returns 0 on success, -1 on fatal error.
 */
int
virNetDevMacVLanCreate(const char *ifname,
                       const char *type,
                       const virMacAddr *macaddress,
                       const char *srcdev,
                       uint32_t macvlan_mode,
                       int *retry)
{
    int rc = -1;
    struct nlmsghdr *resp = NULL;
    struct nlmsgerr *err;
    struct ifinfomsg ifinfo = { .ifi_family = AF_UNSPEC };
    int ifindex;
    unsigned int recvbuflen;
    struct nl_msg *nl_msg;
    struct nlattr *linkinfo, *info_data;
    char macstr[VIR_MAC_STRING_BUFLEN];

    if (virNetDevGetIndex(srcdev, &ifindex) < 0)
        return -1;

    *retry = 0;

    nl_msg = nlmsg_alloc_simple(RTM_NEWLINK,
                                NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);
    if (!nl_msg) {
        virReportOOMError();
        return -1;
    }

    if (nlmsg_append(nl_msg,  &ifinfo, sizeof(ifinfo), NLMSG_ALIGNTO) < 0)
        goto buffer_too_small;

    if (nla_put_u32(nl_msg, IFLA_LINK, ifindex) < 0)
        goto buffer_too_small;

    if (nla_put(nl_msg, IFLA_ADDRESS, VIR_MAC_BUFLEN, macaddress) < 0)
        goto buffer_too_small;

    if (ifname &&
        nla_put(nl_msg, IFLA_IFNAME, strlen(ifname)+1, ifname) < 0)
        goto buffer_too_small;

    if (!(linkinfo = nla_nest_start(nl_msg, IFLA_LINKINFO)))
        goto buffer_too_small;

    if (nla_put(nl_msg, IFLA_INFO_KIND, strlen(type), type) < 0)
        goto buffer_too_small;

    if (macvlan_mode > 0) {
        if (!(info_data = nla_nest_start(nl_msg, IFLA_INFO_DATA)))
            goto buffer_too_small;

        if (nla_put(nl_msg, IFLA_MACVLAN_MODE, sizeof(macvlan_mode),
                    &macvlan_mode) < 0)
            goto buffer_too_small;

        nla_nest_end(nl_msg, info_data);
    }

    nla_nest_end(nl_msg, linkinfo);

    if (virNetlinkCommand(nl_msg, &resp, &recvbuflen, 0, 0,
                          NETLINK_ROUTE, 0) < 0) {
        goto cleanup;
    }

    if (recvbuflen < NLMSG_LENGTH(0) || resp == NULL)
        goto malformed_resp;

    switch (resp->nlmsg_type) {
    case NLMSG_ERROR:
        err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (resp->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
            goto malformed_resp;

        switch (err->error) {

        case 0:
            break;

        case -EEXIST:
            *retry = 1;
            goto cleanup;

        default:
            virReportSystemError(-err->error,
                                 _("error creating %s interface %s@%s (%s)"),
                                 type, ifname, srcdev,
                                 virMacAddrFormat(macaddress, macstr));
            goto cleanup;
        }
        break;

    case NLMSG_DONE:
        break;

    default:
        goto malformed_resp;
    }

    rc = 0;
 cleanup:
    nlmsg_free(nl_msg);
    VIR_FREE(resp);
    return rc;

 malformed_resp:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("malformed netlink response message"));
    goto cleanup;

 buffer_too_small:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("allocated netlink buffer is too small"));
    goto cleanup;
}

/**
 * virNetDevMacVLanDelete:
 *
 * @ifname: Name of the interface
 *
 * Tear down an interface with the given name.
 *
 * Returns 0 on success, -1 on fatal error.
 */
int virNetDevMacVLanDelete(const char *ifname)
{
    return virNetlinkDelLink(ifname, NULL);
}


/**
 * virNetDevMacVLanTapOpen:
 * @ifname: Name of the macvtap interface
 * @tapfd: array of file descriptor return value for the new macvtap device
 * @tapfdSize: number of file descriptors in @tapfd
 * @retries : Number of retries in case udev for example may need to be
 *            waited for to create the tap chardev
 *
 * Open the macvtap's tap device, possibly multiple times if @tapfdSize > 1.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
virNetDevMacVLanTapOpen(const char *ifname,
                        int *tapfd,
                        size_t tapfdSize,
                        int retries)
{
    int ret = -1;
    int ifindex;
    char *tapname = NULL;
    size_t i = 0;

    if (virNetDevGetIndex(ifname, &ifindex) < 0)
        return -1;

    if (virAsprintf(&tapname, "/dev/tap%d", ifindex) < 0)
        goto cleanup;

    for (i = 0; i < tapfdSize; i++) {
        int fd = -1;

        while (fd < 0) {
            if ((fd = open(tapname, O_RDWR)) >= 0) {
                tapfd[i] = fd;
            } else if (retries-- > 0) {
                /* may need to wait for udev to be done */
                usleep(20000);
            } else {
                /* However, if haven't succeeded, quit. */
                virReportSystemError(errno,
                                     _("cannot open macvtap tap device %s"),
                                     tapname);
                goto cleanup;
            }
        }
    }

    ret = 0;

 cleanup:
    if (ret < 0) {
        while (i--)
            VIR_FORCE_CLOSE(tapfd[i]);
    }
    VIR_FREE(tapname);
    return ret;
}


/**
 * virNetDevMacVLanTapSetup:
 * @tapfd: array of file descriptors of the macvtap tap
 * @tapfdSize: number of file descriptors in @tapfd
 * @vnet_hdr: whether to enable or disable IFF_VNET_HDR
 *
 * Turn on the IFF_VNET_HDR flag if requested and available, but make sure
 * it's off otherwise. Similarly, turn on IFF_MULTI_QUEUE if @tapfdSize is
 * greater than one, but if it can't be set, consider it a fatal error
 * (rather than ignoring as with @vnet_hdr).
 *
 * A fatal error is defined as the VNET_HDR flag being set but it cannot
 * be turned off for some reason. This is reported with -1. Other fatal
 * error is not being able to read the interface flags. In that case the
 * macvtap device should not be used.
 *
 * Returns 0 on success, -1 in case of fatal error.
 */
static int
virNetDevMacVLanTapSetup(int *tapfd, size_t tapfdSize, bool vnet_hdr)
{
    unsigned int features;
    struct ifreq ifreq;
    short new_flags = 0;
    size_t i;

    for (i = 0; i < tapfdSize; i++) {
        memset(&ifreq, 0, sizeof(ifreq));

        if (ioctl(tapfd[i], TUNGETIFF, &ifreq) < 0) {
            virReportSystemError(errno, "%s",
                                 _("cannot get interface flags on macvtap tap"));
            return -1;
        }

        new_flags = ifreq.ifr_flags;

        if (vnet_hdr) {
            if (ioctl(tapfd[i], TUNGETFEATURES, &features) < 0) {
                virReportSystemError(errno, "%s",
                                     _("cannot get feature flags on macvtap tap"));
                return -1;
            }
            if (features & IFF_VNET_HDR)
                new_flags |= IFF_VNET_HDR;
        } else {
            new_flags &= ~IFF_VNET_HDR;
        }

# ifdef IFF_MULTI_QUEUE
        if (tapfdSize > 1)
            new_flags |= IFF_MULTI_QUEUE;
        else
            new_flags &= ~IFF_MULTI_QUEUE;
# else
        if (tapfdSize > 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Multiqueue devices are not supported on this system"));
            return -1;
        }
# endif

        if (new_flags != ifreq.ifr_flags) {
            ifreq.ifr_flags = new_flags;
            if (ioctl(tapfd[i], TUNSETIFF, &ifreq) < 0) {
                virReportSystemError(errno, "%s",
                                     _("unable to set vnet or multiqueue flags on macvtap"));
                return -1;
            }
        }
    }

    return 0;
}


static const uint32_t modeMap[VIR_NETDEV_MACVLAN_MODE_LAST] = {
    [VIR_NETDEV_MACVLAN_MODE_VEPA] = MACVLAN_MODE_VEPA,
    [VIR_NETDEV_MACVLAN_MODE_PRIVATE] = MACVLAN_MODE_PRIVATE,
    [VIR_NETDEV_MACVLAN_MODE_BRIDGE] = MACVLAN_MODE_BRIDGE,
    [VIR_NETDEV_MACVLAN_MODE_PASSTHRU] = MACVLAN_MODE_PASSTHRU,
};

/* Struct to hold the state and configuration of a 802.1qbg port */
struct virNetlinkCallbackData {
    char *cr_ifname;
    virNetDevVPortProfilePtr virtPortProfile;
    virMacAddr macaddress;
    char *linkdev;
    int vf;
    unsigned char vmuuid[VIR_UUID_BUFLEN];
    virNetDevVPortProfileOp vmOp;
    unsigned int linkState;
};

typedef struct virNetlinkCallbackData *virNetlinkCallbackDataPtr;

# define INSTANCE_STRLEN 36

static int instance2str(const unsigned char *p, char *dst, size_t size)
{
    if (dst && size > INSTANCE_STRLEN) {
        snprintf(dst, size, "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
                 "%02x%02x-%02x%02x%02x%02x%02x%02x",
                 p[0], p[1], p[2], p[3],
                 p[4], p[5], p[6], p[7],
                 p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
        return 0;
    }
    return -1;
}

# define LLDPAD_PID_FILE  "/var/run/lldpad.pid"
# define VIRIP_PID_FILE   "/var/run/virip.pid"

/**
 * virNetDevMacVLanVPortProfileCallback:
 *
 * @hdr: The buffer containing the received netlink header + payload
 * @length: The length of the received netlink message.
 * @peer: The netling sockaddr containing the peer information
 * @handled: Contains information if the message has been replied to yet
 * @opaque: Contains vital information regarding the associated vm an interface
 *
 * This function is called when a netlink message is received. The function
 * reads the message and responds if it is pertinent to the running VMs
 * network interface.
 */

static void
virNetDevMacVLanVPortProfileCallback(struct nlmsghdr *hdr,
                                     unsigned int length,
                                     struct sockaddr_nl *peer,
                                     bool *handled,
                                     void *opaque)
{
   struct nla_policy ifla_vf_policy[IFLA_VF_MAX + 1] = {
       [IFLA_VF_MAC] = {.minlen = sizeof(struct ifla_vf_mac),
                        .maxlen = sizeof(struct ifla_vf_mac)},
       [IFLA_VF_VLAN] = {.minlen = sizeof(struct ifla_vf_vlan),
                         .maxlen = sizeof(struct ifla_vf_vlan)},
    };

    struct nla_policy ifla_port_policy[IFLA_PORT_MAX + 1] = {
        [IFLA_PORT_RESPONSE] = {.type = NLA_U16},
    };

    struct nlattr *tb[IFLA_MAX + 1], *tb3[IFLA_PORT_MAX + 1],
        *tb_vfinfo[IFLA_VF_MAX + 1], *tb_vfinfo_list;

    struct ifinfomsg ifinfo;
    void *data;
    int rem;
    char *ifname;
    bool indicate = false;
    virNetlinkCallbackDataPtr calld = opaque;
    pid_t lldpad_pid = 0;
    pid_t virip_pid = 0;
    char macaddr[VIR_MAC_STRING_BUFLEN];

    data = nlmsg_data(hdr);

    /* Quickly decide if we want this or not */

    if (virPidFileReadPath(LLDPAD_PID_FILE, &lldpad_pid) < 0)
        return;

    ignore_value(virPidFileReadPath(VIRIP_PID_FILE, &virip_pid));

    if (hdr->nlmsg_pid != lldpad_pid && hdr->nlmsg_pid != virip_pid)
        return; /* we only care for lldpad and virip messages */
    if (hdr->nlmsg_type != RTM_SETLINK)
        return; /* we only care for RTM_SETLINK */
    if (*handled)
        return; /* if it has been handled - dont handle again */

    /* DEBUG start */
    VIR_INFO("netlink message nl_sockaddr: %p len: %d", peer, length);
    VIR_DEBUG("nlmsg_type  = 0x%02x", hdr->nlmsg_type);
    VIR_DEBUG("nlmsg_len   = 0x%04x", hdr->nlmsg_len);
    VIR_DEBUG("nlmsg_pid   = %d", hdr->nlmsg_pid);
    VIR_DEBUG("nlmsg_seq   = 0x%08x", hdr->nlmsg_seq);
    VIR_DEBUG("nlmsg_flags = 0x%04x", hdr->nlmsg_flags);

    VIR_DEBUG("lldpad pid  = %d", lldpad_pid);

    switch (hdr->nlmsg_type) {
    case RTM_NEWLINK:
    case RTM_DELLINK:
    case RTM_SETLINK:
    case RTM_GETLINK:
        VIR_DEBUG(" IFINFOMSG");
        VIR_DEBUG("        ifi_family = 0x%02x",
            ((struct ifinfomsg *)data)->ifi_family);
        VIR_DEBUG("        ifi_type   = 0x%x",
            ((struct ifinfomsg *)data)->ifi_type);
        VIR_DEBUG("        ifi_index  = %i",
            ((struct ifinfomsg *)data)->ifi_index);
        VIR_DEBUG("        ifi_flags  = 0x%04x",
            ((struct ifinfomsg *)data)->ifi_flags);
        VIR_DEBUG("        ifi_change = 0x%04x",
            ((struct ifinfomsg *)data)->ifi_change);
    }
    /* DEBUG end */

    /* Parse netlink message assume a setlink with vfports */
    memcpy(&ifinfo, NLMSG_DATA(hdr), sizeof(ifinfo));
    VIR_DEBUG("family:%#x type:%#x index:%d flags:%#x change:%#x",
        ifinfo.ifi_family, ifinfo.ifi_type, ifinfo.ifi_index,
        ifinfo.ifi_flags, ifinfo.ifi_change);
    if (nlmsg_parse(hdr, sizeof(ifinfo),
        (struct nlattr **)&tb, IFLA_MAX, NULL)) {
        VIR_DEBUG("error parsing request...");
        return;
    }

    if (tb[IFLA_VFINFO_LIST]) {
        VIR_DEBUG("FOUND IFLA_VFINFO_LIST!");

        nla_for_each_nested(tb_vfinfo_list, tb[IFLA_VFINFO_LIST], rem) {
            if (nla_type(tb_vfinfo_list) != IFLA_VF_INFO) {
                VIR_DEBUG("nested parsing of"
                    "IFLA_VFINFO_LIST failed.");
                return;
            }
            if (nla_parse_nested(tb_vfinfo, IFLA_VF_MAX,
                tb_vfinfo_list, ifla_vf_policy)) {
                VIR_DEBUG("nested parsing of "
                    "IFLA_VF_INFO failed.");
                return;
            }
        }

        if (tb_vfinfo[IFLA_VF_MAC]) {
            struct ifla_vf_mac *mac = RTA_DATA(tb_vfinfo[IFLA_VF_MAC]);
            unsigned char *m = mac->mac;

            VIR_DEBUG("IFLA_VF_MAC = %2x:%2x:%2x:%2x:%2x:%2x",
                      m[0], m[1], m[2], m[3], m[4], m[5]);

            if (virMacAddrCmpRaw(&calld->macaddress, mac->mac)) {
                /* Repeat the same check for a broadcast mac */
                size_t i;

                for (i = 0; i < VIR_MAC_BUFLEN; i++) {
                    if (calld->macaddress.addr[i] != 0xff) {
                        VIR_DEBUG("MAC address match failed (wasn't broadcast)");
                        return;
                    }
                }
            }
        }

        if (tb_vfinfo[IFLA_VF_VLAN]) {
            struct ifla_vf_vlan *vlan = RTA_DATA(tb_vfinfo[IFLA_VF_VLAN]);

            VIR_DEBUG("IFLA_VF_VLAN = %d", vlan->vlan);
        }
    }

    if (tb[IFLA_IFNAME]) {
        ifname = (char *)RTA_DATA(tb[IFLA_IFNAME]);
        VIR_DEBUG("IFLA_IFNAME = %s", ifname);
    }

    if (tb[IFLA_OPERSTATE]) {
        rem = *(unsigned short *)RTA_DATA(tb[IFLA_OPERSTATE]);
        VIR_DEBUG("IFLA_OPERSTATE = %d", rem);
    }

    if (tb[IFLA_VF_PORTS]) {
        struct nlattr *tb_vf_ports;

        VIR_DEBUG("found IFLA_VF_PORTS");
        nla_for_each_nested(tb_vf_ports, tb[IFLA_VF_PORTS], rem) {

            VIR_DEBUG("iterating");
            if (nla_type(tb_vf_ports) != IFLA_VF_PORT) {
                VIR_DEBUG("not a IFLA_VF_PORT. skipping");
                continue;
            }
            if (nla_parse_nested(tb3, IFLA_PORT_MAX, tb_vf_ports,
                ifla_port_policy)) {
                VIR_DEBUG("nested parsing on level 2"
                          " failed.");
            }
            if (tb3[IFLA_PORT_VF]) {
                VIR_DEBUG("IFLA_PORT_VF = %d",
                          *(uint32_t *) (RTA_DATA(tb3[IFLA_PORT_VF])));
            }
            if (tb3[IFLA_PORT_PROFILE]) {
                VIR_DEBUG("IFLA_PORT_PROFILE = %s",
                          (char *) RTA_DATA(tb3[IFLA_PORT_PROFILE]));
            }

            if (tb3[IFLA_PORT_VSI_TYPE]) {
                struct ifla_port_vsi *pvsi;
                int tid = 0;

                pvsi = (struct ifla_port_vsi *)
                    RTA_DATA(tb3[IFLA_PORT_VSI_TYPE]);
                tid = ((pvsi->vsi_type_id[2] << 16) |
                       (pvsi->vsi_type_id[1] << 8) |
                       pvsi->vsi_type_id[0]);

                VIR_DEBUG("mgr_id: %d", pvsi->vsi_mgr_id);
                VIR_DEBUG("type_id: %d", tid);
                VIR_DEBUG("type_version: %d",
                          pvsi->vsi_type_version);
            }

            if (tb3[IFLA_PORT_INSTANCE_UUID]) {
                char instance[INSTANCE_STRLEN + 2];
                unsigned char *uuid;

                uuid = (unsigned char *)
                    RTA_DATA(tb3[IFLA_PORT_INSTANCE_UUID]);
                instance2str(uuid, instance, sizeof(instance));
                VIR_DEBUG("IFLA_PORT_INSTANCE_UUID = %s",
                          instance);
            }

            if (tb3[IFLA_PORT_REQUEST]) {
                uint8_t req = *(uint8_t *) RTA_DATA(tb3[IFLA_PORT_REQUEST]);
                VIR_DEBUG("IFLA_PORT_REQUEST = %d", req);

                if (req == PORT_REQUEST_DISASSOCIATE) {
                    VIR_DEBUG("Set dissaccociated.");
                    indicate = true;
                }
            }

            if (tb3[IFLA_PORT_RESPONSE]) {
                VIR_DEBUG("IFLA_PORT_RESPONSE = %d", *(uint16_t *)
                    RTA_DATA(tb3[IFLA_PORT_RESPONSE]));
            }
        }
    }

    if (!indicate)
        return;

    VIR_INFO("Re-send 802.1qbg associate request:");
    VIR_INFO("  if: %s", calld->cr_ifname);
    VIR_INFO("  lf: %s", calld->linkdev);
    VIR_INFO(" mac: %s", virMacAddrFormat(&calld->macaddress, macaddr));
    ignore_value(virNetDevVPortProfileAssociate(calld->cr_ifname,
                                                calld->virtPortProfile,
                                                &calld->macaddress,
                                                calld->linkdev,
                                                calld->vf,
                                                calld->vmuuid,
                                                calld->vmOp, true));
    *handled = true;
    return;
}

/**
 * virNetlinkCallbackDataFree
 *
 * @calld: pointer to a virNetlinkCallbackData object to free
 *
 * This function frees all the data associated with a virNetlinkCallbackData object
 * as well as the object itself. If called with NULL, it does nothing.
 *
 * Returns nothing.
 */
static void
virNetlinkCallbackDataFree(virNetlinkCallbackDataPtr calld)
{
    if (calld) {
        VIR_FREE(calld->cr_ifname);
        VIR_FREE(calld->virtPortProfile);
        VIR_FREE(calld->linkdev);
    }
    VIR_FREE(calld);
}

/**
 * virNetDevMacVLanVPortProfileDestroyCallback:
 *
 * @watch: watch whose handle to remove
 * @macaddr: macaddr whose handle to remove
 * @opaque: Contains vital information regarding the associated vm
 *
 * This function is called when a netlink message handler is terminated.
 * The function frees locally allocated data referenced in the opaque
 * data, and the opaque object itself.
 */
static void
virNetDevMacVLanVPortProfileDestroyCallback(int watch ATTRIBUTE_UNUSED,
                                            const virMacAddr *macaddr ATTRIBUTE_UNUSED,
                                            void *opaque)
{
    virNetlinkCallbackDataFree((virNetlinkCallbackDataPtr)opaque);
}

int
virNetDevMacVLanVPortProfileRegisterCallback(const char *ifname,
                                             const virMacAddr *macaddress,
                                             const char *linkdev,
                                             const unsigned char *vmuuid,
                                             virNetDevVPortProfilePtr virtPortProfile,
                                             virNetDevVPortProfileOp vmOp)
{
    virNetlinkCallbackDataPtr calld = NULL;

    if (virtPortProfile && virNetlinkEventServiceIsRunning(NETLINK_ROUTE)) {
        if (VIR_ALLOC(calld) < 0)
            goto error;
        if (VIR_STRDUP(calld->cr_ifname, ifname) < 0)
            goto error;
        if (VIR_ALLOC(calld->virtPortProfile) < 0)
            goto error;
        memcpy(calld->virtPortProfile, virtPortProfile, sizeof(*virtPortProfile));
        virMacAddrSet(&calld->macaddress, macaddress);
        if (VIR_STRDUP(calld->linkdev, linkdev) < 0)
            goto error;
        memcpy(calld->vmuuid, vmuuid, sizeof(calld->vmuuid));

        calld->vmOp = vmOp;

        if (virNetlinkEventAddClient(virNetDevMacVLanVPortProfileCallback,
                                     virNetDevMacVLanVPortProfileDestroyCallback,
                                     calld, macaddress, NETLINK_ROUTE) < 0)
            goto error;
    }

    return 0;

 error:
    virNetlinkCallbackDataFree(calld);
    return -1;
}


/**
 * virNetDevMacVLanCreateWithVPortProfile:
 * Create an instance of a macvtap device and open its tap character
 * device.

 * @ifnameRequested: Interface name that the caller wants the macvtap
 *    device to have, or NULL to pick the first available name
 *    appropriate for the type (macvlan%d or macvtap%d). If the
 *    suggested name fits one of those patterns, but is already in
 *    use, we will fallback to finding the first available. If the
 *    suggested name *doesn't* fit a pattern and the name is in use,
 *    we will fail.
 * @macaddress: The MAC address for the macvtap device
 * @linkdev: The interface name of the NIC to connect to the external bridge
 * @mode: macvtap mode (VIR_NETDEV_MACVLAN_MODE_(BRIDGE|VEPA|PRIVATE|PASSTHRU)
 * @vmuuid: The UUID of the VM the macvtap belongs to
 * @virtPortProfile: pointer to object holding the virtual port profile data
 * @ifnameResult: Pointer to a string pointer where the actual name of the
 *     interface will be stored into if everything succeeded. It is up
 *     to the caller to free the string.
 * @tapfd: array of file descriptor return value for the new tap device
 * @tapfdSize: number of file descriptors in @tapfd
 * @flags: OR of virNetDevMacVLanCreateFlags.
 *
 * Creates a macvlan device. Optionally, if flags &
 * VIR_NETDEV_MACVLAN_CREATE_WITH_TAP is set, @tapfd is populated with FDs of
 * tap devices up to @tapfdSize.
 *
 * Return 0 on success, -1 on error.
 */
int
virNetDevMacVLanCreateWithVPortProfile(const char *ifnameRequested,
                                       const virMacAddr *macaddress,
                                       const char *linkdev,
                                       virNetDevMacVLanMode mode,
                                       virNetDevVlanPtr vlan,
                                       const unsigned char *vmuuid,
                                       virNetDevVPortProfilePtr virtPortProfile,
                                       char **ifnameResult,
                                       virNetDevVPortProfileOp vmOp,
                                       char *stateDir,
                                       int *tapfd,
                                       size_t tapfdSize,
                                       unsigned int flags)
{
    const char *type = VIR_NET_GENERATED_PREFIX;
    const char *pattern = (flags & VIR_NETDEV_MACVLAN_CREATE_WITH_TAP) ?
        VIR_NET_GENERATED_MACVTAP_PATTERN : VIR_NET_GENERATED_MACVLAN_PATTERN;
    int reservedID = -1;
    char ifname[IFNAMSIZ];
    int retries, do_retry = 0;
    uint32_t macvtapMode;
    const char *ifnameCreated = NULL;
    int vf = -1;
    bool vnet_hdr = flags & VIR_NETDEV_MACVLAN_VNET_HDR;

    macvtapMode = modeMap[mode];

    *ifnameResult = NULL;

    /** Note: When using PASSTHROUGH mode with MACVTAP devices the link
     * device's MAC address must be set to the VMs MAC address. In
     * order to not confuse the first switch or bridge in line this MAC
     * address must be reset when the VM is shut down.
     * This is especially important when using SRIOV capable cards that
     * emulate their switch in firmware.
     */

    if (mode == VIR_NETDEV_MACVLAN_MODE_PASSTHRU) {
        bool setVlan = true;

        if (virtPortProfile &&
            virtPortProfile->virtPortType == VIR_NETDEV_VPORT_PROFILE_8021QBH) {
            /* The Cisco enic driver (the only SRIOV-capable card that
             * uses 802.1Qbh) doesn't support IFLA_VFINFO_LIST, which
             * is required to get/set the vlan tag of a VF.
             */
            setVlan = false;
        }

        if (virNetDevSaveNetConfig(linkdev, -1, stateDir, setVlan) < 0)
           return -1;

        if (virNetDevSetNetConfig(linkdev, -1, NULL, vlan, macaddress, setVlan) < 0)
           return -1;
    }

    if (ifnameRequested) {
        int rc;
        bool isAutoName
            = (STRPREFIX(ifnameRequested, VIR_NET_GENERATED_MACVTAP_PREFIX) ||
               STRPREFIX(ifnameRequested, VIR_NET_GENERATED_MACVLAN_PREFIX));

        VIR_INFO("Requested macvtap device name: %s", ifnameRequested);
        virMutexLock(&virNetDevMacVLanCreateMutex);

        if ((rc = virNetDevExists(ifnameRequested)) < 0) {
            virMutexUnlock(&virNetDevMacVLanCreateMutex);
            return -1;
        }
        if (rc) {
            if (isAutoName)
                goto create_name;
            virReportSystemError(EEXIST,
                                 _("Unable to create %s device %s"),
                                 type, ifnameRequested);
            virMutexUnlock(&virNetDevMacVLanCreateMutex);
            return -1;
        }
        if (isAutoName &&
            (reservedID = virNetDevMacVLanReserveName(ifnameRequested, true)) < 0) {
            reservedID = -1;
            goto create_name;
        }

        if (virNetDevMacVLanCreate(ifnameRequested, type, macaddress,
                                   linkdev, macvtapMode, &do_retry) < 0) {
            if (isAutoName) {
                virNetDevMacVLanReleaseName(ifnameRequested);
                reservedID = -1;
                goto create_name;
            }
            virMutexUnlock(&virNetDevMacVLanCreateMutex);
            return -1;
        }
        /* virNetDevMacVLanCreate() was successful - use this name */
        ifnameCreated = ifnameRequested;
 create_name:
        virMutexUnlock(&virNetDevMacVLanCreateMutex);
    }

    retries = MACVLAN_MAX_ID;
    while (!ifnameCreated && retries) {
        virMutexLock(&virNetDevMacVLanCreateMutex);
        reservedID = virNetDevMacVLanReserveID(reservedID, flags, false, true);
        if (reservedID < 0) {
            virMutexUnlock(&virNetDevMacVLanCreateMutex);
            return -1;
        }
        snprintf(ifname, sizeof(ifname), pattern, reservedID);
        if (virNetDevMacVLanCreate(ifname, type, macaddress, linkdev,
                                   macvtapMode, &do_retry) < 0) {
            virNetDevMacVLanReleaseID(reservedID, flags);
            virMutexUnlock(&virNetDevMacVLanCreateMutex);
            if (!do_retry)
                return -1;
            VIR_INFO("Device %s wasn't reserved but already existed, skipping",
                     ifname);
            retries--;
            continue;
        }
        ifnameCreated = ifname;
        virMutexUnlock(&virNetDevMacVLanCreateMutex);
    }

    if (!ifnameCreated) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Too many unreserved %s devices in use"),
                       type);
        return -1;
    }

    if (virNetDevVPortProfileAssociate(ifnameCreated,
                                       virtPortProfile,
                                       macaddress,
                                       linkdev,
                                       vf,
                                       vmuuid, vmOp, false) < 0)
        goto link_del_exit;

    if (flags & VIR_NETDEV_MACVLAN_CREATE_IFUP) {
        if (virNetDevSetOnline(ifnameCreated, true) < 0)
            goto disassociate_exit;
    }

    if (flags & VIR_NETDEV_MACVLAN_CREATE_WITH_TAP) {
        if (virNetDevMacVLanTapOpen(ifnameCreated, tapfd, tapfdSize, 10) < 0)
            goto disassociate_exit;

        if (virNetDevMacVLanTapSetup(tapfd, tapfdSize, vnet_hdr) < 0)
            goto disassociate_exit;

        if (VIR_STRDUP(*ifnameResult, ifnameCreated) < 0)
            goto disassociate_exit;
    } else {
        if (VIR_STRDUP(*ifnameResult, ifnameCreated) < 0)
            goto disassociate_exit;
    }

    if (vmOp == VIR_NETDEV_VPORT_PROFILE_OP_CREATE ||
        vmOp == VIR_NETDEV_VPORT_PROFILE_OP_RESTORE) {
        /* Only directly register upon a create or restore (restarting
         * a saved image) - migration and libvirtd restart are handled
         * elsewhere.
         */
        if (virNetDevMacVLanVPortProfileRegisterCallback(ifnameCreated, macaddress,
                                                         linkdev, vmuuid,
                                                         virtPortProfile,
                                                         vmOp) < 0)
            goto disassociate_exit;
    }

    return 0;

 disassociate_exit:
    ignore_value(virNetDevVPortProfileDisassociate(ifnameCreated,
                                                   virtPortProfile,
                                                   macaddress,
                                                   linkdev,
                                                   vf,
                                                   vmOp));
    while (tapfdSize--)
        VIR_FORCE_CLOSE(tapfd[tapfdSize]);

 link_del_exit:
    ignore_value(virNetDevMacVLanDelete(ifnameCreated));
    virNetDevMacVLanReleaseName(ifnameCreated);

    return -1;
}


/**
 * virNetDevMacVLanDeleteWithVPortProfile:
 * @ifname : The name of the macvtap interface
 * @linkdev: The interface name of the NIC to connect to the external bridge
 * @virtPortProfile: pointer to object holding the virtual port profile data
 *
 * Delete an interface given its name. Disassociate
 * it with the switch if port profile parameters
 * were provided.
 */
int virNetDevMacVLanDeleteWithVPortProfile(const char *ifname,
                                           const virMacAddr *macaddr,
                                           const char *linkdev,
                                           int mode,
                                           virNetDevVPortProfilePtr virtPortProfile,
                                           char *stateDir)
{
    int ret = 0;

    if (ifname) {
        if (virNetDevVPortProfileDisassociate(ifname,
                                              virtPortProfile,
                                              macaddr,
                                              linkdev,
                                              -1,
                                              VIR_NETDEV_VPORT_PROFILE_OP_DESTROY) < 0)
            ret = -1;
        if (virNetDevMacVLanDelete(ifname) < 0)
            ret = -1;
        virNetDevMacVLanReleaseName(ifname);
    }

    if (mode == VIR_NETDEV_MACVLAN_MODE_PASSTHRU) {
        virMacAddrPtr MAC = NULL;
        virMacAddrPtr adminMAC = NULL;
        virNetDevVlanPtr vlan = NULL;

        if (virNetDevReadNetConfig(linkdev, -1, stateDir,
                                   &adminMAC, &vlan, &MAC) == 0) {

            ignore_value(virNetDevSetNetConfig(linkdev, -1,
                                               adminMAC, vlan, MAC, !!vlan));
            VIR_FREE(MAC);
            VIR_FREE(adminMAC);
            virNetDevVlanFree(vlan);
        }
    }

    virNetlinkEventRemoveClient(0, macaddr, NETLINK_ROUTE);

    return ret;
}

/**
 * virNetDevMacVLanRestartWithVPortProfile:
 * Register a port profile callback handler for a VM that
 * is already running
 * .
 * @cr_ifname: Interface name that the macvtap has.
 * @macaddress: The MAC address for the macvtap device
 * @linkdev: The interface name of the NIC to connect to the external bridge
 * @vmuuid: The UUID of the VM the macvtap belongs to
 * @virtPortProfile: pointer to object holding the virtual port profile data
 * @vmOp: Operation to use during setup of the association
 *
 * Returns 0; returns -1 on error.
 */
int virNetDevMacVLanRestartWithVPortProfile(const char *cr_ifname,
                                            const virMacAddr *macaddress,
                                            const char *linkdev,
                                            const unsigned char *vmuuid,
                                            virNetDevVPortProfilePtr virtPortProfile,
                                            virNetDevVPortProfileOp vmOp)
{
    int rc = 0;

    rc = virNetDevMacVLanVPortProfileRegisterCallback(cr_ifname, macaddress,
                                                      linkdev, vmuuid,
                                                      virtPortProfile, vmOp);
    if (rc < 0)
        goto error;

    ignore_value(virNetDevVPortProfileAssociate(cr_ifname,
                                                virtPortProfile,
                                                macaddress,
                                                linkdev,
                                                -1,
                                                vmuuid,
                                                vmOp, true));

 error:
    return rc;

}

#else /* ! WITH_MACVTAP */
int virNetDevMacVLanCreate(const char *ifname ATTRIBUTE_UNUSED,
                           const char *type ATTRIBUTE_UNUSED,
                           const virMacAddr *macaddress ATTRIBUTE_UNUSED,
                           const char *srcdev ATTRIBUTE_UNUSED,
                           uint32_t macvlan_mode ATTRIBUTE_UNUSED,
                           int *retry ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int virNetDevMacVLanDelete(const char *ifname ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int virNetDevMacVLanCreateWithVPortProfile(const char *ifname ATTRIBUTE_UNUSED,
                                           const virMacAddr *macaddress ATTRIBUTE_UNUSED,
                                           const char *linkdev ATTRIBUTE_UNUSED,
                                           virNetDevMacVLanMode mode ATTRIBUTE_UNUSED,
                                           virNetDevVlanPtr vlan ATTRIBUTE_UNUSED,
                                           const unsigned char *vmuuid ATTRIBUTE_UNUSED,
                                           virNetDevVPortProfilePtr virtPortProfile ATTRIBUTE_UNUSED,
                                           char **res_ifname ATTRIBUTE_UNUSED,
                                           virNetDevVPortProfileOp vmop ATTRIBUTE_UNUSED,
                                           char *stateDir ATTRIBUTE_UNUSED,
                                           int *tapfd ATTRIBUTE_UNUSED,
                                           size_t tapfdSize ATTRIBUTE_UNUSED,
                                           unsigned int unused_flags ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int virNetDevMacVLanDeleteWithVPortProfile(const char *ifname ATTRIBUTE_UNUSED,
                                           const virMacAddr *macaddress ATTRIBUTE_UNUSED,
                                           const char *linkdev ATTRIBUTE_UNUSED,
                                           int mode ATTRIBUTE_UNUSED,
                                           virNetDevVPortProfilePtr virtPortProfile ATTRIBUTE_UNUSED,
                                           char *stateDir ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int virNetDevMacVLanRestartWithVPortProfile(const char *cr_ifname ATTRIBUTE_UNUSED,
                                            const virMacAddr *macaddress ATTRIBUTE_UNUSED,
                                            const char *linkdev ATTRIBUTE_UNUSED,
                                            const unsigned char *vmuuid ATTRIBUTE_UNUSED,
                                            virNetDevVPortProfilePtr virtPortProfile ATTRIBUTE_UNUSED,
                                            virNetDevVPortProfileOp vmOp ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int virNetDevMacVLanVPortProfileRegisterCallback(const char *ifname ATTRIBUTE_UNUSED,
                                                 const virMacAddr *macaddress ATTRIBUTE_UNUSED,
                                                 const char *linkdev ATTRIBUTE_UNUSED,
                                                 const unsigned char *vmuuid ATTRIBUTE_UNUSED,
                                                 virNetDevVPortProfilePtr virtPortProfile ATTRIBUTE_UNUSED,
                                                 virNetDevVPortProfileOp vmOp ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int virNetDevMacVLanReleaseName(const char *name ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int virNetDevMacVLanReserveName(const char *name ATTRIBUTE_UNUSED,
                                bool quietFail ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}
#endif /* ! WITH_MACVTAP */
