/*
 * Copyright (C) 2010-2011 Red Hat, Inc.
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

#include "virnetdevmacvlan.h"
#include "virmacaddr.h"
#include "util.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_NET

#define virNetDevError(code, ...)                                       \
    virReportErrorHelper(VIR_FROM_NET, code, __FILE__,                  \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


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

# include <linux/if.h>
# include <linux/if_tun.h>

/* Older kernels lacked this enum value.  */
# if !HAVE_DECL_MACVLAN_MODE_PASSTHRU
#  define MACVLAN_MODE_PASSTHRU 8
# endif

# include "memory.h"
# include "logging.h"
# include "uuid.h"
# include "virfile.h"
# include "virnetlink.h"
# include "virnetdev.h"
# include "virpidfile.h"


# define MACVTAP_NAME_PREFIX	"macvtap"
# define MACVTAP_NAME_PATTERN	"macvtap%d"

# define MACVLAN_NAME_PREFIX	"macvlan"
# define MACVLAN_NAME_PATTERN	"macvlan%d"

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
                       const unsigned char *macaddress,
                       const char *srcdev,
                       uint32_t macvlan_mode,
                       int *retry)
{
    int rc = -1;
    struct nlmsghdr *resp;
    struct nlmsgerr *err;
    struct ifinfomsg ifinfo = { .ifi_family = AF_UNSPEC };
    int ifindex;
    unsigned char *recvbuf = NULL;
    unsigned int recvbuflen;
    struct nl_msg *nl_msg;
    struct nlattr *linkinfo, *info_data;

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

    if (virNetlinkCommand(nl_msg, &recvbuf, &recvbuflen, 0) < 0) {
        goto cleanup;
    }

    if (recvbuflen < NLMSG_LENGTH(0) || recvbuf == NULL)
        goto malformed_resp;

    resp = (struct nlmsghdr *)recvbuf;

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
                                 _("error creating %s type of interface"),
                                 type);
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
    VIR_FREE(recvbuf);
    return rc;

malformed_resp:
    virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("malformed netlink response message"));
    goto cleanup;

buffer_too_small:
    virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
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
    int rc = -1;
    struct nlmsghdr *resp;
    struct nlmsgerr *err;
    struct ifinfomsg ifinfo = { .ifi_family = AF_UNSPEC };
    unsigned char *recvbuf = NULL;
    unsigned int recvbuflen;
    struct nl_msg *nl_msg;

    nl_msg = nlmsg_alloc_simple(RTM_DELLINK,
                                NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);
    if (!nl_msg) {
        virReportOOMError();
        return -1;
    }

    if (nlmsg_append(nl_msg,  &ifinfo, sizeof(ifinfo), NLMSG_ALIGNTO) < 0)
        goto buffer_too_small;

    if (nla_put(nl_msg, IFLA_IFNAME, strlen(ifname)+1, ifname) < 0)
        goto buffer_too_small;

    if (virNetlinkCommand(nl_msg, &recvbuf, &recvbuflen, 0) < 0) {
        goto cleanup;
    }

    if (recvbuflen < NLMSG_LENGTH(0) || recvbuf == NULL)
        goto malformed_resp;

    resp = (struct nlmsghdr *)recvbuf;

    switch (resp->nlmsg_type) {
    case NLMSG_ERROR:
        err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (resp->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
            goto malformed_resp;

        if (err->error) {
            virReportSystemError(-err->error,
                                 _("error destroying %s interface"),
                                 ifname);
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
    VIR_FREE(recvbuf);
    return rc;

malformed_resp:
    virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("malformed netlink response message"));
    goto cleanup;

buffer_too_small:
    virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("allocated netlink buffer is too small"));
    goto cleanup;
}


/**
 * virNetDevMacVLanTapOpen:
 * Open the macvtap's tap device.
 * @ifname: Name of the macvtap interface
 * @retries : Number of retries in case udev for example may need to be
 *            waited for to create the tap chardev
 * Returns negative value in case of error, the file descriptor otherwise.
 */
static
int virNetDevMacVLanTapOpen(const char *ifname,
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
        VIR_FORCE_FCLOSE(file);
        return -1;
    }

    VIR_FORCE_FCLOSE(file);

    if (snprintf(tapname, sizeof(tapname),
                 "/dev/tap%d", ifindex) >= sizeof(tapname)) {
        virReportSystemError(errno,
                             "%s",
                             _("internal buffer for tap device is too small"));
        return -1;
    }

    while (1) {
        /* may need to wait for udev to be done */
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


/**
 * virNetDevMacVLanTapSetup:
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
virNetDevMacVLanTapSetup(int tapfd, int vnet_hdr)
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
        if (ioctl(tapfd, TUNGETFEATURES, &features) < 0) {
            virReportSystemError(errno, "%s",
                   _("cannot get feature flags on macvtap tap"));
            return -1;
        }
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
    unsigned char *macaddress;
    char *linkdev;
    int vf;
    unsigned char *vmuuid;
    enum virNetDevVPortProfileOp vmOp;
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
 * @msg: The buffer containing the received netlink message
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
virNetDevMacVLanVPortProfileCallback(unsigned char *msg,
                                     int length,
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
    struct nlmsghdr *hdr;
    void *data;
    int rem;
    char *ifname;
    bool indicate = false;
    virNetlinkCallbackDataPtr calld = opaque;
    pid_t lldpad_pid = 0;
    pid_t virip_pid = 0;

    hdr = (struct nlmsghdr *) msg;
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
        VIR_DEBUG(" IFINFOMSG\n");
        VIR_DEBUG("        ifi_family = 0x%02x\n",
            ((struct ifinfomsg *)data)->ifi_family);
        VIR_DEBUG("        ifi_type   = 0x%x\n",
            ((struct ifinfomsg *)data)->ifi_type);
        VIR_DEBUG("        ifi_index  = %i\n",
            ((struct ifinfomsg *)data)->ifi_index);
        VIR_DEBUG("        ifi_flags  = 0x%04x\n",
            ((struct ifinfomsg *)data)->ifi_flags);
        VIR_DEBUG("        ifi_change = 0x%04x\n",
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

            if (memcmp(calld->macaddress, m, VIR_MAC_BUFLEN))
            {
                /* Repeat the same check for a broadcast mac */
                int i;

                for (i = 0;i < VIR_MAC_BUFLEN; i++) {
                    if (calld->macaddress[i] != 0xff) {
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
        VIR_DEBUG("IFLA_IFNAME = %s\n", ifname);
    }

    if (tb[IFLA_OPERSTATE]) {
        rem = *(unsigned short *)RTA_DATA(tb[IFLA_OPERSTATE]);
        VIR_DEBUG("IFLA_OPERSTATE = %d\n", rem);
    }

    if (tb[IFLA_VF_PORTS]) {
        struct nlattr *tb_vf_ports;

        VIR_DEBUG("found IFLA_VF_PORTS\n");
        nla_for_each_nested(tb_vf_ports, tb[IFLA_VF_PORTS], rem) {

            VIR_DEBUG("iterating\n");
            if (nla_type(tb_vf_ports) != IFLA_VF_PORT) {
                VIR_DEBUG("not a IFLA_VF_PORT. skipping\n");
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
                VIR_DEBUG("IFLA_PORT_INSTANCE_UUID = %s\n",
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
                VIR_DEBUG("IFLA_PORT_RESPONSE = %d\n", *(uint16_t *)
                    RTA_DATA(tb3[IFLA_PORT_RESPONSE]));
            }
        }
    }

    if (!indicate) {
        return;
    }

    VIR_INFO("Re-send 802.1qbg associate request:");
    VIR_INFO("  if: %s", calld->cr_ifname);
    VIR_INFO("  lf: %s", calld->linkdev);
    VIR_INFO(" mac: %02x:%02x:%02x:%02x:%02x:%02x",
             calld->macaddress[0], calld->macaddress[1],
             calld->macaddress[2], calld->macaddress[3],
             calld->macaddress[4], calld->macaddress[5]);

    ignore_value(virNetDevVPortProfileAssociate(calld->cr_ifname,
                                                calld->virtPortProfile,
                                                calld->macaddress,
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
        VIR_FREE(calld->macaddress);
        VIR_FREE(calld->linkdev);
        VIR_FREE(calld->vmuuid);
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
                                            const unsigned char *macaddr ATTRIBUTE_UNUSED,
                                            void *opaque)
{
    virNetlinkCallbackDataFree((virNetlinkCallbackDataPtr)opaque);
}

static int
virNetDevMacVLanVPortProfileRegisterCallback(const char *ifname,
                                             const unsigned char *macaddress,
                                             const char *linkdev,
                                             const unsigned char *vmuuid,
                                             virNetDevVPortProfilePtr virtPortProfile,
                                             enum virNetDevVPortProfileOp vmOp)
{
    virNetlinkCallbackDataPtr calld = NULL;

    if (virtPortProfile && virNetlinkEventServiceIsRunning()) {
        if (VIR_ALLOC(calld) < 0)
            goto memory_error;
        if ((calld->cr_ifname = strdup(ifname)) == NULL)
            goto memory_error;
        if (VIR_ALLOC(calld->virtPortProfile) < 0)
            goto memory_error;
        memcpy(calld->virtPortProfile, virtPortProfile, sizeof(*virtPortProfile));
        if (VIR_ALLOC_N(calld->macaddress, VIR_MAC_BUFLEN) < 0)
            goto memory_error;
        memcpy(calld->macaddress, macaddress, VIR_MAC_BUFLEN);
        if ((calld->linkdev = strdup(linkdev)) == NULL)
            goto  memory_error;
        if (VIR_ALLOC_N(calld->vmuuid, VIR_UUID_BUFLEN) < 0)
            goto memory_error;
        memcpy(calld->vmuuid, vmuuid, VIR_UUID_BUFLEN);

        calld->vmOp = vmOp;

        if (virNetlinkEventAddClient(virNetDevMacVLanVPortProfileCallback,
                                     virNetDevMacVLanVPortProfileDestroyCallback,
                                     calld, macaddress) < 0)
            goto error;
    }

    return 0;

memory_error:
    virReportOOMError();
error:
    virNetlinkCallbackDataFree(calld);
    return -1;
}


/**
 * virNetDevMacVLanCreateWithVPortProfile:
 * Create an instance of a macvtap device and open its tap character
 * device.
 * @tgifname: Interface name that the macvtap is supposed to have. May
 *    be NULL if this function is supposed to choose a name
 * @macaddress: The MAC address for the macvtap device
 * @linkdev: The interface name of the NIC to connect to the external bridge
 * @mode: int describing the mode for 'bridge', 'vepa', 'private' or 'passthru'.
 * @vnet_hdr: 1 to enable IFF_VNET_HDR, 0 to disable it
 * @vmuuid: The UUID of the VM the macvtap belongs to
 * @virtPortProfile: pointer to object holding the virtual port profile data
 * @res_ifname: Pointer to a string pointer where the actual name of the
 *     interface will be stored into if everything succeeded. It is up
 *     to the caller to free the string.
 *
 * Returns file descriptor of the tap device in case of success with @withTap,
 * otherwise returns 0; returns -1 on error.
 */
int virNetDevMacVLanCreateWithVPortProfile(const char *tgifname,
                                           const unsigned char *macaddress,
                                           const char *linkdev,
                                           enum virNetDevMacVLanMode mode,
                                           bool withTap,
                                           int vnet_hdr,
                                           const unsigned char *vmuuid,
                                           virNetDevVPortProfilePtr virtPortProfile,
                                           char **res_ifname,
                                           enum virNetDevVPortProfileOp vmOp,
                                           char *stateDir,
                                           virNetDevBandwidthPtr bandwidth)
{
    const char *type = withTap ? "macvtap" : "macvlan";
    const char *prefix = withTap ? MACVTAP_NAME_PREFIX : MACVLAN_NAME_PREFIX;
    const char *pattern = withTap ? MACVTAP_NAME_PATTERN : MACVLAN_NAME_PATTERN;
    int c, rc;
    char ifname[IFNAMSIZ];
    int retries, do_retry = 0;
    uint32_t macvtapMode;
    const char *cr_ifname;
    int ret;
    int vf = -1;

    macvtapMode = modeMap[mode];

    *res_ifname = NULL;

    VIR_DEBUG("%s: VM OPERATION: %s", __FUNCTION__, virNetDevVPortProfileOpTypeToString(vmOp));

    /** Note: When using PASSTHROUGH mode with MACVTAP devices the link
     * device's MAC address must be set to the VMs MAC address. In
     * order to not confuse the first switch or bridge in line this MAC
     * address must be reset when the VM is shut down.
     * This is especially important when using SRIOV capable cards that
     * emulate their switch in firmware.
     */
    if (mode == VIR_NETDEV_MACVLAN_MODE_PASSTHRU) {
        if (virNetDevReplaceMacAddress(linkdev, macaddress, stateDir) < 0)
            return -1;
    }

    if (tgifname) {
        if ((ret = virNetDevExists(tgifname)) < 0)
            return -1;

        if (ret) {
            if (STRPREFIX(tgifname, prefix)) {
                goto create_name;
            }
            virReportSystemError(EEXIST,
                                 _("Unable to create macvlan device %s"), tgifname);
            return -1;
        }
        cr_ifname = tgifname;
        rc = virNetDevMacVLanCreate(tgifname, type, macaddress, linkdev,
                                    macvtapMode, &do_retry);
        if (rc < 0)
            return -1;
    } else {
create_name:
        retries = 5;
        for (c = 0; c < 8192; c++) {
            snprintf(ifname, sizeof(ifname), pattern, c);
            if ((ret = virNetDevExists(ifname)) < 0)
                return -1;
            if (!ret) {
                rc = virNetDevMacVLanCreate(ifname, type, macaddress, linkdev,
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

    if (virNetDevVPortProfileAssociate(cr_ifname,
                                       virtPortProfile,
                                       macaddress,
                                       linkdev,
                                       vf,
                                       vmuuid, vmOp, false) < 0) {
        rc = -1;
        goto link_del_exit;
    }

    if (virNetDevSetOnline(cr_ifname, true) < 0) {
        rc = -1;
        goto disassociate_exit;
    }

    if (withTap) {
        if ((rc = virNetDevMacVLanTapOpen(cr_ifname, 10)) < 0)
            goto disassociate_exit;

        if (virNetDevMacVLanTapSetup(rc, vnet_hdr) < 0) {
            VIR_FORCE_CLOSE(rc); /* sets rc to -1 */
            goto disassociate_exit;
        }
        if (!(*res_ifname = strdup(cr_ifname))) {
            VIR_FORCE_CLOSE(rc); /* sets rc to -1 */
            virReportOOMError();
            goto disassociate_exit;
        }
    } else {
        if (!(*res_ifname = strdup(cr_ifname))) {
            virReportOOMError();
            goto disassociate_exit;
        }
        rc = 0;
    }

    if (virNetDevBandwidthSet(cr_ifname, bandwidth) < 0) {
        virNetDevError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot set bandwidth limits on %s"),
                       cr_ifname);
        if (withTap)
            VIR_FORCE_CLOSE(rc); /* sets rc to -1 */
        else
            rc = -1;
        goto disassociate_exit;
    }

    if (virNetDevMacVLanVPortProfileRegisterCallback(cr_ifname, macaddress,
                                         linkdev, vmuuid, virtPortProfile, vmOp) < 0 )
        goto disassociate_exit;

    return rc;

disassociate_exit:
    ignore_value(virNetDevVPortProfileDisassociate(cr_ifname,
                                                   virtPortProfile,
                                                   macaddress,
                                                   linkdev,
                                                   vf,
                                                   vmOp));

link_del_exit:
    ignore_value(virNetDevMacVLanDelete(cr_ifname));

    return rc;
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
                                           const unsigned char *macaddr,
                                           const char *linkdev,
                                           int mode,
                                           virNetDevVPortProfilePtr virtPortProfile,
                                           char *stateDir)
{
    int ret = 0;
    int vf = -1;

    if (mode == VIR_NETDEV_MACVLAN_MODE_PASSTHRU) {
        ignore_value(virNetDevRestoreMacAddress(linkdev, stateDir));
    }

    if (ifname) {
        if (virNetDevVPortProfileDisassociate(ifname,
                                              virtPortProfile,
                                              macaddr,
                                              linkdev,
                                              vf,
                                              VIR_NETDEV_VPORT_PROFILE_OP_DESTROY) < 0)
            ret = -1;
        if (virNetDevMacVLanDelete(ifname) < 0)
            ret = -1;
    }

    virNetlinkEventRemoveClient(0, macaddr);

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
                                           const unsigned char *macaddress,
                                           const char *linkdev,
                                           const unsigned char *vmuuid,
                                           virNetDevVPortProfilePtr virtPortProfile,
                                           enum virNetDevVPortProfileOp vmOp)
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
                           const unsigned char *macaddress ATTRIBUTE_UNUSED,
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
                                           const unsigned char *macaddress ATTRIBUTE_UNUSED,
                                           const char *linkdev ATTRIBUTE_UNUSED,
                                           enum virNetDevMacVLanMode mode ATTRIBUTE_UNUSED,
                                           bool withTap ATTRIBUTE_UNUSED,
                                           int vnet_hdr ATTRIBUTE_UNUSED,
                                           const unsigned char *vmuuid ATTRIBUTE_UNUSED,
                                           virNetDevVPortProfilePtr virtPortProfile ATTRIBUTE_UNUSED,
                                           char **res_ifname ATTRIBUTE_UNUSED,
                                           enum virNetDevVPortProfileOp vmop ATTRIBUTE_UNUSED,
                                           char *stateDir ATTRIBUTE_UNUSED,
                                           virNetDevBandwidthPtr bandwidth ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int virNetDevMacVLanDeleteWithVPortProfile(const char *ifname ATTRIBUTE_UNUSED,
                                           const unsigned char *macaddress ATTRIBUTE_UNUSED,
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
                                           const unsigned char *macaddress ATTRIBUTE_UNUSED,
                                           const char *linkdev ATTRIBUTE_UNUSED,
                                           const unsigned char *vmuuid ATTRIBUTE_UNUSED,
                                           virNetDevVPortProfilePtr virtPortProfile ATTRIBUTE_UNUSED,
                                           enum virNetDevVPortProfileOp vmOp ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}
#endif /* ! WITH_MACVTAP */
