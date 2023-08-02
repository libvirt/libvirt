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
 * Notes: iproute2 package
 */

#include <config.h>

#include "virnetdevmacvlan.h"
#include "virmacaddr.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NET

VIR_ENUM_IMPL(virNetDevMacVLanMode,
              VIR_NETDEV_MACVLAN_MODE_LAST,
              "vepa",
              "private",
              "bridge",
              "passthrough",
);

#if defined(WITH_LIBNL)
# include <fcntl.h>

# include <net/if.h>
# include <linux/if_tun.h>

# include "viralloc.h"
# include "virlog.h"
# include "viruuid.h"
# include "virfile.h"
# include "virnetlink.h"
# include "virnetdev.h"
# include "virpidfile.h"
# include "virbitmap.h"
# include "virsocket.h"

VIR_LOG_INIT("util.netdevmacvlan");


/**
 * virNetDevMacVLanIsMacvtap:
 * @ifname: Name of the interface
 *
 * Return T if the named netdev exists and is a macvtap device
 * F in all other cases.
 */
bool
virNetDevMacVLanIsMacvtap(const char *ifname)
{
    int ifindex;
    g_autofree char *tapname = NULL;

    if (virNetDevGetIndex(ifname, &ifindex) < 0)
        return false;

    tapname = g_strdup_printf("/dev/tap%d", ifindex);

    return virFileExists(tapname);
}


/**
 * virNetDevMacVLanCreate:
 *
 * @ifname: The name the interface is supposed to have; optional parameter
 * @macaddress: The MAC address of the device
 * @srcdev: The name of the 'link' device
 * @macvlan_mode: The macvlan mode to use
 * @flags: OR of virNetDevMacVLanCreateFlags.
 *
 * Create a macvtap device with the given properties.
 *
 * Returns 0 on success, -1 on fatal error.
 */
int
virNetDevMacVLanCreate(const char *ifname,
                       const virMacAddr *macaddress,
                       const char *srcdev,
                       uint32_t macvlan_mode,
                       unsigned int flags)
{
    int error = 0;
    int ifindex = 0;
    const char *type = (flags & VIR_NETDEV_MACVLAN_CREATE_WITH_TAP ?
                        "macvtap" : "macvlan");
    virNetlinkNewLinkData data = {
        .macvlan_mode = &macvlan_mode,
        .mac = macaddress,
    };

    if (virNetDevGetIndex(srcdev, &ifindex) < 0)
        return -1;

    data.ifindex = &ifindex;
    if (virNetlinkNewLink(ifname, type, &data, &error) < 0) {
        char macstr[VIR_MAC_STRING_BUFLEN];

        virReportSystemError(-error,
                             _("error creating %1$s interface %2$s@%3$s (%4$s)"),
                             type, ifname, srcdev,
                             virMacAddrFormat(macaddress, macstr));
        return -1;
    }

    VIR_INFO("created device: '%s'", ifname);
    return 0;
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
    VIR_INFO("delete device: '%s'", ifname);
    return virNetlinkDelLink(ifname, NULL);
}


/**
 * virNetDevMacVLanTapOpen:
 * @ifname: Name of the macvtap interface
 * @tapfd: array of file descriptor return value for the new macvtap device
 * @tapfdSize: number of file descriptors in @tapfd
 *
 * Open the macvtap's tap device, possibly multiple times if @tapfdSize > 1.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
virNetDevMacVLanTapOpen(const char *ifname,
                        int *tapfd,
                        size_t tapfdSize)
{
    int retries = 10;
    int ret = -1;
    int ifindex;
    size_t i = 0;
    g_autofree char *tapname = NULL;

    if (virNetDevGetIndex(ifname, &ifindex) < 0)
        return -1;

    tapname = g_strdup_printf("/dev/tap%d", ifindex);

    for (i = 0; i < tapfdSize; i++) {
        int fd = -1;

        while (fd < 0) {
            if ((fd = open(tapname, O_RDWR)) >= 0) {
                tapfd[i] = fd;
            } else if (retries-- > 0) {
                /* may need to wait for udev to be done */
                g_usleep(20000);
            } else {
                /* However, if haven't succeeded, quit. */
                virReportSystemError(errno,
                                     _("cannot open macvtap tap device %1$s"),
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
int
virNetDevMacVLanTapSetup(int *tapfd, size_t tapfdSize, bool vnet_hdr)
{
    unsigned int features;
    short new_flags = 0;
    size_t i;

    for (i = 0; i < tapfdSize; i++) {
        struct ifreq ifreq = { 0 };

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

        if (tapfdSize > 1)
            new_flags |= IFF_MULTI_QUEUE;
        else
            new_flags &= ~IFF_MULTI_QUEUE;

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
    virNetDevVPortProfile *virtPortProfile;
    virMacAddr macaddress;
    char *linkdev;
    int vf;
    unsigned char vmuuid[VIR_UUID_BUFLEN];
    virNetDevVPortProfileOp vmOp;
    unsigned int linkState;
};

# define INSTANCE_STRLEN 36

static int instance2str(const unsigned char *p, char *dst, size_t size)
{
    if (dst && size > INSTANCE_STRLEN) {
        g_snprintf(dst, size, "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
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
    struct virNetlinkCallbackData *calld = opaque;
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
                    VIR_DEBUG("Set disassociated.");
                    indicate = true;
                }
            }

            if (tb3[IFLA_PORT_RESPONSE]) {
                VIR_DEBUG("IFLA_PORT_RESPONSE = %d",
                          *(uint16_t *) RTA_DATA(tb3[IFLA_PORT_RESPONSE]));
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
virNetlinkCallbackDataFree(struct virNetlinkCallbackData *calld)
{
    if (calld) {
        g_free(calld->cr_ifname);
        g_free(calld->virtPortProfile);
        g_free(calld->linkdev);
    }
    g_free(calld);
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
virNetDevMacVLanVPortProfileDestroyCallback(int watch G_GNUC_UNUSED,
                                            const virMacAddr *macaddr G_GNUC_UNUSED,
                                            void *opaque)
{
    virNetlinkCallbackDataFree((struct virNetlinkCallbackData *)opaque);
}

int
virNetDevMacVLanVPortProfileRegisterCallback(const char *ifname,
                                             const virMacAddr *macaddress,
                                             const char *linkdev,
                                             const unsigned char *vmuuid,
                                             const virNetDevVPortProfile *virtPortProfile,
                                             virNetDevVPortProfileOp vmOp)
{
    struct virNetlinkCallbackData *calld = NULL;

    if (virtPortProfile && virNetlinkEventServiceIsRunning(NETLINK_ROUTE)) {
        calld = g_new0(struct virNetlinkCallbackData, 1);
        calld->cr_ifname = g_strdup(ifname);
        calld->virtPortProfile = g_new0(virNetDevVPortProfile, 1);
        memcpy(calld->virtPortProfile, virtPortProfile, sizeof(*virtPortProfile));
        virMacAddrSet(&calld->macaddress, macaddress);
        calld->linkdev = g_strdup(linkdev);
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
                                       const virNetDevVlan *vlan,
                                       const unsigned char *vmuuid,
                                       const virNetDevVPortProfile *virtPortProfile,
                                       char **ifnameResult,
                                       virNetDevVPortProfileOp vmOp,
                                       char *stateDir,
                                       int *tapfd,
                                       size_t tapfdSize,
                                       unsigned int flags)
{
    g_autofree char *ifname = NULL;
    uint32_t macvtapMode;
    int vf = -1;
    bool vnet_hdr = flags & VIR_NETDEV_MACVLAN_VNET_HDR;
    virNetDevGenNameType type;

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
        VIR_INFO("Requested macvtap device name: %s", ifnameRequested);
        ifname = g_strdup(ifnameRequested);
    }

    if (flags & VIR_NETDEV_MACVLAN_CREATE_WITH_TAP)
        type = VIR_NET_DEV_GEN_NAME_MACVTAP;
    else
        type = VIR_NET_DEV_GEN_NAME_MACVLAN;

    if (virNetDevGenerateName(&ifname, type) < 0 ||
        virNetDevMacVLanCreate(ifname, macaddress,
                               linkdev, macvtapMode, flags) < 0) {
        return -1;
    }

    if (virNetDevVPortProfileAssociate(ifname,
                                       virtPortProfile,
                                       macaddress,
                                       linkdev,
                                       vf,
                                       vmuuid, vmOp, false) < 0) {
        goto link_del_exit;
    }

    if (flags & VIR_NETDEV_MACVLAN_CREATE_IFUP) {
        if (virNetDevSetOnline(ifname, true) < 0)
            goto disassociate_exit;
    }

    if (flags & VIR_NETDEV_MACVLAN_CREATE_WITH_TAP) {
        if (virNetDevMacVLanTapOpen(ifname, tapfd, tapfdSize) < 0)
            goto disassociate_exit;

        if (virNetDevMacVLanTapSetup(tapfd, tapfdSize, vnet_hdr) < 0)
            goto disassociate_exit;
    }

    if (vmOp == VIR_NETDEV_VPORT_PROFILE_OP_CREATE ||
        vmOp == VIR_NETDEV_VPORT_PROFILE_OP_RESTORE) {
        /* Only directly register upon a create or restore (restarting
         * a saved image) - migration and libvirtd restart are handled
         * elsewhere.
         */
        if (virNetDevMacVLanVPortProfileRegisterCallback(ifname, macaddress,
                                                         linkdev, vmuuid,
                                                         virtPortProfile,
                                                         vmOp) < 0)
            goto disassociate_exit;
    }

    *ifnameResult = g_steal_pointer(&ifname);
    return 0;

 disassociate_exit:
    ignore_value(virNetDevVPortProfileDisassociate(ifname,
                                                   virtPortProfile,
                                                   macaddress,
                                                   linkdev,
                                                   vf,
                                                   vmOp));
    while (tapfdSize--)
        VIR_FORCE_CLOSE(tapfd[tapfdSize]);

 link_del_exit:
    ignore_value(virNetDevMacVLanDelete(ifname));
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
                                           const virNetDevVPortProfile *virtPortProfile,
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
    }

    if (mode == VIR_NETDEV_MACVLAN_MODE_PASSTHRU) {
        g_autoptr(virMacAddr) MAC = NULL;
        g_autoptr(virMacAddr) adminMAC = NULL;
        g_autoptr(virNetDevVlan) vlan = NULL;

        if ((virNetDevReadNetConfig(linkdev, -1, stateDir,
                                    &adminMAC, &vlan, &MAC) == 0) &&
            (adminMAC || vlan || MAC)) {

            ignore_value(virNetDevSetNetConfig(linkdev, -1,
                                               adminMAC, vlan, MAC, !!vlan));
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
                                            const virNetDevVPortProfile *virtPortProfile,
                                            virNetDevVPortProfileOp vmOp)
{
    int rc = 0;

    rc = virNetDevMacVLanVPortProfileRegisterCallback(cr_ifname, macaddress,
                                                      linkdev, vmuuid,
                                                      virtPortProfile, vmOp);
    if (rc < 0)
        return rc;

    ignore_value(virNetDevVPortProfileAssociate(cr_ifname,
                                                virtPortProfile,
                                                macaddress,
                                                linkdev,
                                                -1,
                                                vmuuid,
                                                vmOp, true));

    return rc;

}

#else /* ! WITH_LIBNL */
bool virNetDevMacVLanIsMacvtap(const char *ifname G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return false;
}

int virNetDevMacVLanCreate(const char *ifname G_GNUC_UNUSED,
                           const virMacAddr *macaddress G_GNUC_UNUSED,
                           const char *srcdev G_GNUC_UNUSED,
                           uint32_t macvlan_mode G_GNUC_UNUSED,
                           unsigned int fflags G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int virNetDevMacVLanDelete(const char *ifname G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int
virNetDevMacVLanTapOpen(const char *ifname G_GNUC_UNUSED,
                        int *tapfd G_GNUC_UNUSED,
                        size_t tapfdSize G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int
virNetDevMacVLanTapSetup(int *tapfd G_GNUC_UNUSED,
                         size_t tapfdSize G_GNUC_UNUSED,
                         bool vnet_hdr G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int virNetDevMacVLanCreateWithVPortProfile(const char *ifname G_GNUC_UNUSED,
                                           const virMacAddr *macaddress G_GNUC_UNUSED,
                                           const char *linkdev G_GNUC_UNUSED,
                                           virNetDevMacVLanMode mode G_GNUC_UNUSED,
                                           const virNetDevVlan *vlan G_GNUC_UNUSED,
                                           const unsigned char *vmuuid G_GNUC_UNUSED,
                                           const virNetDevVPortProfile *virtPortProfile G_GNUC_UNUSED,
                                           char **res_ifname G_GNUC_UNUSED,
                                           virNetDevVPortProfileOp vmop G_GNUC_UNUSED,
                                           char *stateDir G_GNUC_UNUSED,
                                           int *tapfd G_GNUC_UNUSED,
                                           size_t tapfdSize G_GNUC_UNUSED,
                                           unsigned int unused_flags G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int virNetDevMacVLanDeleteWithVPortProfile(const char *ifname G_GNUC_UNUSED,
                                           const virMacAddr *macaddress G_GNUC_UNUSED,
                                           const char *linkdev G_GNUC_UNUSED,
                                           int mode G_GNUC_UNUSED,
                                           const virNetDevVPortProfile *virtPortProfile G_GNUC_UNUSED,
                                           char *stateDir G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int virNetDevMacVLanRestartWithVPortProfile(const char *cr_ifname G_GNUC_UNUSED,
                                            const virMacAddr *macaddress G_GNUC_UNUSED,
                                            const char *linkdev G_GNUC_UNUSED,
                                            const unsigned char *vmuuid G_GNUC_UNUSED,
                                            const virNetDevVPortProfile *virtPortProfile G_GNUC_UNUSED,
                                            virNetDevVPortProfileOp vmOp G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}

int virNetDevMacVLanVPortProfileRegisterCallback(const char *ifname G_GNUC_UNUSED,
                                                 const virMacAddr *macaddress G_GNUC_UNUSED,
                                                 const char *linkdev G_GNUC_UNUSED,
                                                 const unsigned char *vmuuid G_GNUC_UNUSED,
                                                 const virNetDevVPortProfile *virtPortProfile G_GNUC_UNUSED,
                                                 virNetDevVPortProfileOp vmOp G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot create macvlan devices on this platform"));
    return -1;
}
#endif /* ! WITH_LIBNL */
