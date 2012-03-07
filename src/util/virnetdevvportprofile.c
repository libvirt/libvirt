/*
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virnetdevvportprofile.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_NET

#define virNetDevError(code, ...)                                       \
    virReportErrorHelper(VIR_FROM_NET, code, __FILE__,                  \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


VIR_ENUM_IMPL(virNetDevVPortProfileOp, VIR_NETDEV_VPORT_PROFILE_OP_LAST,
              "create",
              "save",
              "restore",
              "destroy",
              "migrate out",
              "migrate in start",
              "migrate in finish",
              "no-op")

#if WITH_VIRTUALPORT

# include <stdint.h>
# include <stdio.h>
# include <errno.h>
# include <fcntl.h>
# include <c-ctype.h>
# include <sys/socket.h>
# include <sys/ioctl.h>

# include <linux/if.h>
# include <linux/if_tun.h>

# include "virnetlink.h"
# include "virfile.h"
# include "memory.h"
# include "logging.h"
# include "virnetdev.h"

# define MICROSEC_PER_SEC       (1000 * 1000)

# define NLMSGBUF_SIZE  256
# define RATTBUF_SIZE   64


# define STATUS_POLL_TIMEOUT_USEC (10 * MICROSEC_PER_SEC)
# define STATUS_POLL_INTERVL_USEC (MICROSEC_PER_SEC / 8)

# define LLDPAD_PID_FILE  "/var/run/lldpad.pid"


enum virNetDevVPortProfileLinkOp {
    VIR_NETDEV_VPORT_PROFILE_LINK_OP_ASSOCIATE = 0x1,
    VIR_NETDEV_VPORT_PROFILE_LINK_OP_DISASSOCIATE = 0x2,
    VIR_NETDEV_VPORT_PROFILE_LINK_OP_PREASSOCIATE = 0x3,
    VIR_NETDEV_VPORT_PROFILE_LINK_OP_PREASSOCIATE_RR = 0x4,
};

#endif

bool
virNetDevVPortProfileEqual(virNetDevVPortProfilePtr a, virNetDevVPortProfilePtr b)
{
    /* NULL resistant */
    if (!a && !b)
        return true;

    if (!a || !b)
        return false;

    if (a->virtPortType != b->virtPortType)
        return false;

    switch (a->virtPortType) {
    case VIR_NETDEV_VPORT_PROFILE_NONE:
        break;

    case VIR_NETDEV_VPORT_PROFILE_8021QBG:
        if (a->u.virtPort8021Qbg.managerID != b->u.virtPort8021Qbg.managerID ||
            a->u.virtPort8021Qbg.typeID != b->u.virtPort8021Qbg.typeID ||
            a->u.virtPort8021Qbg.typeIDVersion != b->u.virtPort8021Qbg.typeIDVersion ||
            memcmp(a->u.virtPort8021Qbg.instanceID, b->u.virtPort8021Qbg.instanceID, VIR_UUID_BUFLEN) != 0)
            return false;
        break;

    case VIR_NETDEV_VPORT_PROFILE_8021QBH:
        if (STRNEQ(a->u.virtPort8021Qbh.profileID, b->u.virtPort8021Qbh.profileID))
            return false;
        break;

    default:
        break;
    }

    return true;
}


#if WITH_VIRTUALPORT

static struct nla_policy ifla_port_policy[IFLA_PORT_MAX + 1] =
{
  [IFLA_PORT_RESPONSE]      = { .type = NLA_U16 },
};

static uint32_t
virNetDevVPortProfileGetLldpadPid(void) {
    int fd;
    uint32_t pid = 0;

    fd = open(LLDPAD_PID_FILE, O_RDONLY);
    if (fd >= 0) {
        char buffer[10];

        if (saferead(fd, buffer, sizeof(buffer)) <= sizeof(buffer)) {
            unsigned int res;
            char *endptr;

            if (virStrToLong_ui(buffer, &endptr, 10, &res) == 0
                && (*endptr == '\0' || c_isspace(*endptr))
                && res != 0) {
                pid = res;
            } else {
                virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("error parsing pid of lldpad"));
            }
        }
    } else {
        virReportSystemError(errno,
                             _("Error opening file %s"), LLDPAD_PID_FILE);
    }

    VIR_FORCE_CLOSE(fd);

    return pid;
}

/**
 * virNetDevVPortProfileGetStatus:
 *
 * tb: top level netlink response attributes + values
 * vf: The virtual function used in the request
 * instanceId: instanceId of the interface (vm uuid in case of 802.1Qbh)
 * is8021Qbg: whether this function is call for 8021Qbg
 * status: pointer to a uint16 where the status will be written into
 *
 * Get the status from the IFLA_PORT_RESPONSE field; Returns 0 in
 * case of success, < 0 otherwise with error having been reported
 */
static int
virNetDevVPortProfileGetStatus(struct nlattr **tb, int32_t vf,
                               const unsigned char *instanceId,
                               bool nltarget_kernel,
                               bool is8021Qbg,
                               uint16_t *status)
{
    int rc = -1;
    struct nlattr *tb_port[IFLA_PORT_MAX + 1] = { NULL, };

    if (vf == PORT_SELF_VF && nltarget_kernel) {
        if (tb[IFLA_PORT_SELF]) {
            if (nla_parse_nested(tb_port, IFLA_PORT_MAX, tb[IFLA_PORT_SELF],
                                 ifla_port_policy)) {
                virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("error parsing IFLA_PORT_SELF part"));
                goto cleanup;
            }
        } else {
            virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("IFLA_PORT_SELF is missing"));
            goto cleanup;
        }
    } else {
        if (tb[IFLA_VF_PORTS]) {
            int rem;
            bool found = false;
            struct nlattr *tb_vf_ports = { NULL, };

            nla_for_each_nested(tb_vf_ports, tb[IFLA_VF_PORTS], rem) {

                if (nla_type(tb_vf_ports) != IFLA_VF_PORT) {
                    virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("error while iterating over "
                                     "IFLA_VF_PORTS part"));
                    goto cleanup;
                }

                if (nla_parse_nested(tb_port, IFLA_PORT_MAX, tb_vf_ports,
                                     ifla_port_policy)) {
                    virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("error parsing IFLA_VF_PORT part"));
                    goto cleanup;
                }

                if (instanceId &&
                    tb_port[IFLA_PORT_INSTANCE_UUID] &&
                    !memcmp(instanceId,
                            (unsigned char *)
                                   RTA_DATA(tb_port[IFLA_PORT_INSTANCE_UUID]),
                            VIR_UUID_BUFLEN) &&
                    tb_port[IFLA_PORT_VF] &&
                    vf == *(uint32_t *)RTA_DATA(tb_port[IFLA_PORT_VF])) {
                        found = true;
                        break;
                }
            }

            if (!found) {
                virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Could not find netlink response with "
                                 "expected parameters"));
                goto cleanup;
            }
        } else {
            virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("IFLA_VF_PORTS is missing"));
            goto cleanup;
        }
    }

    if (tb_port[IFLA_PORT_RESPONSE]) {
        *status = *(uint16_t *)RTA_DATA(tb_port[IFLA_PORT_RESPONSE]);
        rc = 0;
    } else {
        if (is8021Qbg) {
            /* no in-progress here; may be missing */
            *status = PORT_PROFILE_RESPONSE_INPROGRESS;
            rc = 0;
        } else {
            virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("no IFLA_PORT_RESPONSE found in netlink message"));
            goto cleanup;
        }
    }
cleanup:
    return rc;
}


static int
virNetDevVPortProfileOpSetLink(const char *ifname, int ifindex,
                               bool nltarget_kernel,
                               const unsigned char *macaddr,
                               int vlanid,
                               const char *profileId,
                               struct ifla_port_vsi *portVsi,
                               const unsigned char *instanceId,
                               const unsigned char *hostUUID,
                               int32_t vf,
                               uint8_t op)
{
    int rc = -1;
    struct nlmsghdr *resp;
    struct nlmsgerr *err;
    struct ifinfomsg ifinfo = {
        .ifi_family = AF_UNSPEC,
        .ifi_index  = ifindex,
    };
    unsigned char *recvbuf = NULL;
    unsigned int recvbuflen = 0;
    uint32_t pid = 0;
    struct nl_msg *nl_msg;
    struct nlattr *vfports = NULL, *vfport;

    nl_msg = nlmsg_alloc_simple(RTM_SETLINK, NLM_F_REQUEST);
    if (!nl_msg) {
        virReportOOMError();
        return rc;
    }

    if (nlmsg_append(nl_msg,  &ifinfo, sizeof(ifinfo), NLMSG_ALIGNTO) < 0)
        goto buffer_too_small;

    if (ifname &&
        nla_put(nl_msg, IFLA_IFNAME, strlen(ifname)+1, ifname) < 0)
        goto buffer_too_small;

    if (macaddr || vlanid >= 0) {
        struct nlattr *vfinfolist, *vfinfo;

        if (!(vfinfolist = nla_nest_start(nl_msg, IFLA_VFINFO_LIST)))
            goto buffer_too_small;

        if (!(vfinfo = nla_nest_start(nl_msg, IFLA_VF_INFO)))
            goto buffer_too_small;

        if (macaddr) {
            struct ifla_vf_mac ifla_vf_mac = {
                .vf = vf,
                .mac = { 0, },
            };

            memcpy(ifla_vf_mac.mac, macaddr, 6);

            if (nla_put(nl_msg, IFLA_VF_MAC, sizeof(ifla_vf_mac),
                        &ifla_vf_mac) < 0)
                goto buffer_too_small;
        }

        if (vlanid >= 0) {
            struct ifla_vf_vlan ifla_vf_vlan = {
                .vf = vf,
                .vlan = vlanid,
                .qos = 0,
            };

            if (nla_put(nl_msg, IFLA_VF_VLAN, sizeof(ifla_vf_vlan),
                        &ifla_vf_vlan) < 0)
                goto buffer_too_small;
        }

        nla_nest_end(nl_msg, vfinfo);
        nla_nest_end(nl_msg, vfinfolist);
    }

    if (vf == PORT_SELF_VF && nltarget_kernel) {
        if (!(vfport = nla_nest_start(nl_msg, IFLA_PORT_SELF)))
            goto buffer_too_small;
    } else {
        if (!(vfports = nla_nest_start(nl_msg, IFLA_VF_PORTS)))
            goto buffer_too_small;

        /* begin nesting vfports */
        if (!(vfport = nla_nest_start(nl_msg, IFLA_VF_PORT)))
            goto buffer_too_small;
    }

    if (profileId) {
        if (nla_put(nl_msg, IFLA_PORT_PROFILE, strlen(profileId) + 1,
                    profileId) < 0)
            goto buffer_too_small;
    }

    if (portVsi) {
        if (nla_put(nl_msg, IFLA_PORT_VSI_TYPE, sizeof(*portVsi),
                    portVsi) < 0)
            goto buffer_too_small;
    }

    if (instanceId) {
        if (nla_put(nl_msg, IFLA_PORT_INSTANCE_UUID, VIR_UUID_BUFLEN,
                    instanceId) < 0)
            goto buffer_too_small;
    }

    if (hostUUID) {
        if (nla_put(nl_msg, IFLA_PORT_HOST_UUID, VIR_UUID_BUFLEN,
                    hostUUID) < 0)
            goto buffer_too_small;
    }

    if (vf != PORT_SELF_VF) {
        if (nla_put(nl_msg, IFLA_PORT_VF, sizeof(vf), &vf) < 0)
            goto buffer_too_small;
    }

    if (nla_put(nl_msg, IFLA_PORT_REQUEST, sizeof(op), &op) < 0)
        goto buffer_too_small;

    /* end nesting of vport */
    nla_nest_end(nl_msg, vfport);

    if (vfports) {
        /* end nesting of vfports */
        nla_nest_end(nl_msg, vfports);
    }

    if (!nltarget_kernel) {
        pid = virNetDevVPortProfileGetLldpadPid();
        if (pid == 0)
            goto cleanup;
    }

    if (virNetlinkCommand(nl_msg, &recvbuf, &recvbuflen, pid) < 0)
        goto cleanup;

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
                _("error during virtual port configuration of ifindex %d"),
                ifindex);
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
 * virNetDevVPortProfileGetNthParent
 *
 * @ifname : the name of the interface; ignored if ifindex is valid
 * @ifindex : the index of the interface or -1 if ifname is given
 * @nthParent : the nth parent interface to get
 * @parent_ifindex : pointer to int
 * @parent_ifname : pointer to buffer of size IFNAMSIZ
 * @nth : the nth parent that is actually returned; if for example eth0.100
 *        was given and the 100th parent is to be returned, then eth0 will
 *        most likely be returned with nth set to 1 since the chain does
 *        not have more interfaces
 *
 * Get the nth parent interface of the given interface. 0 is the interface
 * itself.
 *
 * Return 0 on success, < 0 otherwise
 */
static int
virNetDevVPortProfileGetNthParent(const char *ifname, int ifindex, unsigned int nthParent,
                                  int *parent_ifindex, char *parent_ifname,
                                  unsigned int *nth)
{
    int rc;
    struct nlattr *tb[IFLA_MAX + 1] = { NULL, };
    unsigned char *recvbuf = NULL;
    bool end = false;
    unsigned int i = 0;

    *nth = 0;

    if (ifindex <= 0 && virNetDevGetIndex(ifname, &ifindex) < 0)
        return -1;

    while (!end && i <= nthParent) {
        rc = virNetDevLinkDump(ifname, ifindex, true, tb, &recvbuf, NULL);
        if (rc < 0)
            break;

        if (tb[IFLA_IFNAME]) {
            if (!virStrcpy(parent_ifname, (char*)RTA_DATA(tb[IFLA_IFNAME]),
                           IFNAMSIZ)) {
                virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("buffer for root interface name is too small"));
                VIR_FREE(recvbuf);
                return -1;
            }
            *parent_ifindex = ifindex;
        }

        if (tb[IFLA_LINK]) {
            ifindex = *(int *)RTA_DATA(tb[IFLA_LINK]);
            ifname = NULL;
        } else
            end = true;

        VIR_FREE(recvbuf);

        i++;
    }

    *nth = i - 1;

    return rc;
}


/* Returns 0 on success, -1 on general failure, and -2 on timeout */
static int
virNetDevVPortProfileOpCommon(const char *ifname, int ifindex,
                              bool nltarget_kernel,
                              const unsigned char *macaddr,
                              int vlanid,
                              const char *profileId,
                              struct ifla_port_vsi *portVsi,
                              const unsigned char *instanceId,
                              const unsigned char *hostUUID,
                              int32_t vf,
                              uint8_t op,
                              bool setlink_only)
{
    int rc;
    unsigned char *recvbuf = NULL;
    struct nlattr *tb[IFLA_MAX + 1] = { NULL , };
    int repeats = STATUS_POLL_TIMEOUT_USEC / STATUS_POLL_INTERVL_USEC;
    uint16_t status = 0;
    bool is8021Qbg = (profileId == NULL);

    rc = virNetDevVPortProfileOpSetLink(ifname, ifindex,
                                        nltarget_kernel,
                                        macaddr,
                                        vlanid,
                                        profileId,
                                        portVsi,
                                        instanceId,
                                        hostUUID,
                                        vf,
                                        op);
    if (rc < 0) {
        virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("sending of PortProfileRequest failed."));
        return rc;
    }

    if (setlink_only) /*for re-associations on existing links*/
        return 0;

    while (--repeats >= 0) {
        rc = virNetDevLinkDump(NULL, ifindex, nltarget_kernel, tb,
                               &recvbuf, virNetDevVPortProfileGetLldpadPid);
        if (rc < 0)
            goto cleanup;

        rc = virNetDevVPortProfileGetStatus(tb, vf, instanceId, nltarget_kernel,
                                            is8021Qbg, &status);
        if (rc < 0)
            goto cleanup;
        if (status == PORT_PROFILE_RESPONSE_SUCCESS ||
            status == PORT_VDP_RESPONSE_SUCCESS) {
            break;
        } else if (status == PORT_PROFILE_RESPONSE_INPROGRESS) {
            /* keep trying... */
        } else {
            virReportSystemError(EINVAL,
                    _("error %d during port-profile setlink on "
                      "interface %s (%d)"),
                    status, ifname, ifindex);
            rc = -1;
            break;
        }

        usleep(STATUS_POLL_INTERVL_USEC);

        VIR_FREE(recvbuf);
    }

    if (status == PORT_PROFILE_RESPONSE_INPROGRESS) {
        virNetDevError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("port-profile setlink timed out"));
        rc = -2;
    }

cleanup:
    VIR_FREE(recvbuf);

    return rc;
}


static int
virNetDevVPortProfileGetPhysdevAndVlan(const char *ifname, int *root_ifindex, char *root_ifname,
                                       int *vlanid)
{
    int ret;
    unsigned int nth;
    int ifindex = -1;

    *vlanid = -1;
    while (1) {
        if ((ret = virNetDevVPortProfileGetNthParent(ifname, ifindex, 1,
                                                     root_ifindex, root_ifname, &nth)) < 0)
            return ret;
        if (nth == 0)
            break;
        if (*vlanid == -1) {
            if (virNetDevGetVLanID(root_ifname, vlanid) < 0) {
                virResetLastError();
                *vlanid = -1;
            }
        }

        ifindex = *root_ifindex;
        ifname = NULL;
    }

    return 0;
}

/* Returns 0 on success, -1 on general failure, and -2 on timeout */
static int
virNetDevVPortProfileOp8021Qbg(const char *ifname,
                               const unsigned char *macaddr,
                               int vf,
                               const virNetDevVPortProfilePtr virtPort,
                               enum virNetDevVPortProfileLinkOp virtPortOp,
                               bool setlink_only)
{
    int rc = -1;
    int op = PORT_REQUEST_ASSOCIATE;
    struct ifla_port_vsi portVsi = {
        .vsi_mgr_id       = virtPort->u.virtPort8021Qbg.managerID,
        .vsi_type_version = virtPort->u.virtPort8021Qbg.typeIDVersion,
    };
    bool nltarget_kernel = false;
    int vlanid;
    int physdev_ifindex = 0;
    char physdev_ifname[IFNAMSIZ] = { 0, };

    if (!ifname)
        return -1;

    vf = PORT_SELF_VF;

    if (virNetDevVPortProfileGetPhysdevAndVlan(ifname, &physdev_ifindex,
                                               physdev_ifname, &vlanid) < 0) {
        goto cleanup;
    }

    if (vlanid < 0)
        vlanid = 0;

    portVsi.vsi_type_id[2] = virtPort->u.virtPort8021Qbg.typeID >> 16;
    portVsi.vsi_type_id[1] = virtPort->u.virtPort8021Qbg.typeID >> 8;
    portVsi.vsi_type_id[0] = virtPort->u.virtPort8021Qbg.typeID;

    switch (virtPortOp) {
    case VIR_NETDEV_VPORT_PROFILE_LINK_OP_PREASSOCIATE:
        op = PORT_REQUEST_PREASSOCIATE;
        break;
    case VIR_NETDEV_VPORT_PROFILE_LINK_OP_ASSOCIATE:
        op = PORT_REQUEST_ASSOCIATE;
        break;
    case VIR_NETDEV_VPORT_PROFILE_LINK_OP_DISASSOCIATE:
        op = PORT_REQUEST_DISASSOCIATE;
        break;
    default:
        virNetDevError(VIR_ERR_INTERNAL_ERROR,
                       _("operation type %d not supported"), virtPortOp);
        goto cleanup;
    }

    rc = virNetDevVPortProfileOpCommon(physdev_ifname, physdev_ifindex,
                                       nltarget_kernel,
                                       macaddr,
                                       vlanid,
                                       NULL,
                                       &portVsi,
                                       virtPort->u.virtPort8021Qbg.instanceID,
                                       NULL,
                                       vf,
                                       op,
                                       setlink_only);
cleanup:
    return rc;
}

/* Returns 0 on success, -1 on general failure, and -2 on timeout */
static int
virNetDevVPortProfileOp8021Qbh(const char *ifname,
                               const unsigned char *macaddr,
                               int32_t vf,
                               const virNetDevVPortProfilePtr virtPort,
                               const unsigned char *vm_uuid,
                               enum virNetDevVPortProfileLinkOp virtPortOp)
{
    int rc = 0;
    char *physfndev = NULL;
    unsigned char hostuuid[VIR_UUID_BUFLEN];
    bool nltarget_kernel = true;
    int ifindex;
    int vlanid = -1;
    bool is_vf = false;

    if (vf == -1) {
        int isvf_ret = virNetDevIsVirtualFunction(ifname);

        if (isvf_ret == -1)
            goto cleanup;
        is_vf = !!isvf_ret;
    }

    if (is_vf) {
        if (virNetDevGetVirtualFunctionInfo(ifname, &physfndev, &vf) < 0) {
            rc = -1;
            goto cleanup;
        }
    } else {
        physfndev = strdup(ifname);
        if (!physfndev) {
            virReportOOMError();
            rc = -1;
            goto cleanup;
        }
    }

    rc = virNetDevGetIndex(physfndev, &ifindex);
    if (rc < 0)
        goto cleanup;

    switch (virtPortOp) {
    case VIR_NETDEV_VPORT_PROFILE_LINK_OP_PREASSOCIATE_RR:
    case VIR_NETDEV_VPORT_PROFILE_LINK_OP_ASSOCIATE:
        errno = virGetHostUUID(hostuuid);
        if (errno) {
            rc = -1;
            goto cleanup;
        }

        rc = virNetDevVPortProfileOpCommon(NULL, ifindex,
                                           nltarget_kernel,
                                           macaddr,
                                           vlanid,
                                           virtPort->u.virtPort8021Qbh.profileID,
                                           NULL,
                                           vm_uuid,
                                           hostuuid,
                                           vf,
                                           (virtPortOp ==
                                            VIR_NETDEV_VPORT_PROFILE_LINK_OP_PREASSOCIATE_RR) ?
                                           PORT_REQUEST_PREASSOCIATE_RR
                                           : PORT_REQUEST_ASSOCIATE,
                                           false);
        if (rc == -2)
            /* Association timed out, disassociate */
            virNetDevVPortProfileOpCommon(NULL, ifindex,
                                          nltarget_kernel,
                                          NULL,
                                          vlanid,
                                          NULL,
                                          NULL,
                                          NULL,
                                          NULL,
                                          vf,
                                          PORT_REQUEST_DISASSOCIATE,
                                          false);
        break;

    case VIR_NETDEV_VPORT_PROFILE_LINK_OP_DISASSOCIATE:
        rc = virNetDevVPortProfileOpCommon(NULL, ifindex,
                                           nltarget_kernel,
                                           NULL,
                                           vlanid,
                                           NULL,
                                           NULL,
                                           NULL,
                                           NULL,
                                           vf,
                                           PORT_REQUEST_DISASSOCIATE,
                                           false);
        break;

    default:
        virNetDevError(VIR_ERR_INTERNAL_ERROR,
                       _("operation type %d not supported"), virtPortOp);
        rc = -1;
    }

cleanup:
    VIR_FREE(physfndev);
    return rc;
}

/**
 * virNetDevVPortProfileAssociate:
 *
 * @macvtap_ifname: The name of the macvtap device
 * @virtPort: pointer to the object holding port profile parameters
 * @vmuuid : the UUID of the virtual machine
 * @vmOp : The VM operation (i.e., create, no-op)
 * @setlink_only : Only set the link - dont wait for the link to come up
 *
 * Associate a port on a swtich with a profile. This function
 * may notify a kernel driver or an external daemon to run
 * the setup protocol. If profile parameters were not supplied
 * by the user, then this function returns without doing
 * anything.
 *
 * Returns 0 in case of success, < 0 otherwise with error
 * having been reported.
 */
int
virNetDevVPortProfileAssociate(const char *macvtap_ifname,
                               const virNetDevVPortProfilePtr virtPort,
                               const unsigned char *macvtap_macaddr,
                               const char *linkdev,
                               int vf,
                               const unsigned char *vmuuid,
                               enum virNetDevVPortProfileOp vmOp,
                               bool setlink_only)
{
    int rc = 0;

    VIR_DEBUG("Associating port profile '%p' on link device '%s'",
              virtPort, (macvtap_ifname ? macvtap_ifname : linkdev));

    VIR_DEBUG("%s: VM OPERATION: %s", __FUNCTION__, virNetDevVPortProfileOpTypeToString(vmOp));

    if (!virtPort || vmOp == VIR_NETDEV_VPORT_PROFILE_OP_NO_OP)
        return 0;

    switch (virtPort->virtPortType) {
    case VIR_NETDEV_VPORT_PROFILE_NONE:
    case VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH:
    case VIR_NETDEV_VPORT_PROFILE_LAST:
        break;

    case VIR_NETDEV_VPORT_PROFILE_8021QBG:
        rc = virNetDevVPortProfileOp8021Qbg(macvtap_ifname, macvtap_macaddr,
                                            vf, virtPort,
                                            (vmOp == VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_START)
                                            ? VIR_NETDEV_VPORT_PROFILE_LINK_OP_PREASSOCIATE
                                            : VIR_NETDEV_VPORT_PROFILE_LINK_OP_ASSOCIATE,
                                            setlink_only);
        break;

    case VIR_NETDEV_VPORT_PROFILE_8021QBH:
        rc = virNetDevVPortProfileOp8021Qbh(linkdev, macvtap_macaddr, vf,
                                            virtPort, vmuuid,
                                            (vmOp == VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_START)
                                            ? VIR_NETDEV_VPORT_PROFILE_LINK_OP_PREASSOCIATE_RR
                                            : VIR_NETDEV_VPORT_PROFILE_LINK_OP_ASSOCIATE);
        if (vmOp != VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_START && !rc) {
            /* XXX bogus error handling */
            ignore_value(virNetDevSetOnline(linkdev, true));
        }

        break;
    }

    return rc;
}


/**
 * virNetDevVPortProfileDisassociate:
 *
 * @macvtap_ifname: The name of the macvtap device
 * @macvtap_macaddr : The MAC address of the macvtap
 * @linkdev: The link device in case of macvtap
 * @virtPort: point to object holding port profile parameters
 *
 * Returns 0 in case of success, != 0 otherwise with error
 * having been reported.
 */
int
virNetDevVPortProfileDisassociate(const char *macvtap_ifname,
                                  const virNetDevVPortProfilePtr virtPort,
                                  const unsigned char *macvtap_macaddr,
                                  const char *linkdev,
                                  int vf,
                                  enum virNetDevVPortProfileOp vmOp)
{
    int rc = 0;

    VIR_DEBUG("Disassociating port profile id '%p' on link device '%s' ",
              virtPort, macvtap_ifname);

    VIR_DEBUG("%s: VM OPERATION: %s", __FUNCTION__, virNetDevVPortProfileOpTypeToString(vmOp));

    if (!virtPort)
       return 0;

    switch (virtPort->virtPortType) {
    case VIR_NETDEV_VPORT_PROFILE_NONE:
    case VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH:
    case VIR_NETDEV_VPORT_PROFILE_LAST:
        break;

    case VIR_NETDEV_VPORT_PROFILE_8021QBG:
        rc = virNetDevVPortProfileOp8021Qbg(macvtap_ifname, macvtap_macaddr, vf,
                                            virtPort,
                                            VIR_NETDEV_VPORT_PROFILE_LINK_OP_DISASSOCIATE, false);
        break;

    case VIR_NETDEV_VPORT_PROFILE_8021QBH:
        /* avoid disassociating twice */
        if (vmOp == VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_FINISH)
            break;
        ignore_value(virNetDevSetOnline(linkdev, false));
        rc = virNetDevVPortProfileOp8021Qbh(linkdev, macvtap_macaddr, vf,
                                            virtPort, NULL,
                                            VIR_NETDEV_VPORT_PROFILE_LINK_OP_DISASSOCIATE);
        break;
    }

    return rc;
}

#else /* ! WITH_VIRTUALPORT */
int virNetDevVPortProfileAssociate(const char *macvtap_ifname ATTRIBUTE_UNUSED,
                               const virNetDevVPortProfilePtr virtPort ATTRIBUTE_UNUSED,
                               const unsigned char *macvtap_macaddr ATTRIBUTE_UNUSED,
                               const char *linkdev ATTRIBUTE_UNUSED,
                               int vf ATTRIBUTE_UNUSED,
                               const unsigned char *vmuuid ATTRIBUTE_UNUSED,
                               enum virNetDevVPortProfileOp vmOp ATTRIBUTE_UNUSED,
                               bool setlink_only ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Virtual port profile association not supported on this platform"));
    return -1;
}

int virNetDevVPortProfileDisassociate(const char *macvtap_ifname ATTRIBUTE_UNUSED,
                                      const virNetDevVPortProfilePtr virtPort ATTRIBUTE_UNUSED,
                                      const unsigned char *macvtap_macaddr ATTRIBUTE_UNUSED,
                                      const char *linkdev ATTRIBUTE_UNUSED,
                                      int vf ATTRIBUTE_UNUSED,
                                      enum virNetDevVPortProfileOp vmOp ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Virtual port profile association not supported on this platform"));
    return -1;
}
#endif /* ! WITH_VIRTUALPORT */
