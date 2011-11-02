/*
 * interface.c: interface support functions
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corp.
 * Copyright (C) 2010 Stefan Berger
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
 * chgIfaceFlags originated from bridge.c
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#include <config.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netinet/in.h>

#ifdef __linux__
# include <linux/if.h>
# include <linux/sockios.h>
# include <linux/if_vlan.h>
#endif

#include "internal.h"

#include "util.h"
#include "interface.h"
#include "virterror_internal.h"
#include "virfile.h"
#include "memory.h"
#include "netlink.h"
#include "pci.h"
#include "logging.h"
#include "virnetdev.h"

#define VIR_FROM_THIS VIR_FROM_NET

#define ifaceError(code, ...) \
        virReportErrorHelper(VIR_FROM_NET, code, __FILE__, \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

/**
 * ifaceCheck
 *
 * @reportError: whether to report errors or keep silent
 * @ifname: Name of the interface
 * @macaddr: expected MAC address of the interface; not checked if NULL
 * @ifindex: expected index of the interface; not checked if '-1'
 *
 * Determine whether a given interface is still available. If so,
 * it must have the given MAC address and if an interface index is
 * passed, it must also match the interface index.
 *
 * Returns 0 on success, -errno on failure.
 *   -ENODEV : if interface with given name does not exist or its interface
 *             index is different than the one passed
 *   -EINVAL : if interface name is invalid (too long)
 */
#ifdef __linux__
int
ifaceCheck(bool reportError, const char *ifname,
           const unsigned char *macaddr, int ifindex)
{
    struct ifreq ifr;
    int fd = -1;
    int rc = 0;
    int idx;

    if (macaddr != NULL) {
        fd = socket(PF_PACKET, SOCK_DGRAM, 0);
        if (fd < 0)
            return -errno;

        memset(&ifr, 0, sizeof(ifr));

        if (virStrncpy(ifr.ifr_name,
                       ifname, strlen(ifname), sizeof(ifr.ifr_name)) == NULL) {
            if (reportError)
                ifaceError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid interface name %s"),
                           ifname);
            rc = -EINVAL;
            goto cleanup;
        }

        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
            if (reportError)
                ifaceError(VIR_ERR_INTERNAL_ERROR,
                           _("coud not get MAC address of interface %s"),
                           ifname);
            rc = -errno;
            goto cleanup;
        }

        if (memcmp(&ifr.ifr_hwaddr.sa_data, macaddr, VIR_MAC_BUFLEN) != 0) {
            rc = -ENODEV;
            goto cleanup;
        }
    }

    if (ifindex != -1) {
        rc = ifaceGetIndex(reportError, ifname, &idx);
        if (rc == 0 && idx != ifindex)
            rc = -ENODEV;
    }

 cleanup:
    VIR_FORCE_CLOSE(fd);

    return rc;
}

#else

int
ifaceCheck(bool reportError ATTRIBUTE_UNUSED,
           const char *ifname ATTRIBUTE_UNUSED,
           const unsigned char *macaddr ATTRIBUTE_UNUSED,
           int ifindex ATTRIBUTE_UNUSED)
{
    return -ENOSYS;
}

#endif /* __linux__ */


/**
 * ifaceGetIndex
 *
 * @reportError: whether to report errors or keep silent
 * @ifname : Name of the interface whose index is to be found
 * @ifindex: Pointer to int where the index will be written into
 *
 * Get the index of an interface given its name.
 *
 * Returns 0 on success, -errno on failure.
 *   -ENODEV : if interface with given name does not exist
 *   -EINVAL : if interface name is invalid (too long)
 */
#ifdef __linux__
int
ifaceGetIndex(bool reportError, const char *ifname, int *ifindex)
{
    int rc = 0;
    struct ifreq ifreq;
    int fd = socket(PF_PACKET, SOCK_DGRAM, 0);

    if (fd < 0)
        return -errno;

    memset(&ifreq, 0, sizeof(ifreq));

    if (virStrncpy(ifreq.ifr_name, ifname, strlen(ifname),
                   sizeof(ifreq.ifr_name)) == NULL) {
        if (reportError)
            ifaceError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid interface name %s"),
                       ifname);
        rc = -EINVAL;
        goto cleanup;
    }

    if (ioctl(fd, SIOCGIFINDEX, &ifreq) >= 0)
        *ifindex = ifreq.ifr_ifindex;
    else {
        if (reportError)
            ifaceError(VIR_ERR_INTERNAL_ERROR,
                       _("interface %s does not exist"),
                       ifname);
        rc = -ENODEV;
    }

cleanup:
    VIR_FORCE_CLOSE(fd);

    return rc;
}

#else

int
ifaceGetIndex(bool reportError,
              const char *ifname ATTRIBUTE_UNUSED,
              int *ifindex ATTRIBUTE_UNUSED)
{
    if (reportError) {
        ifaceError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("ifaceGetIndex is not supported on non-linux platforms"));
    }

    return -ENOSYS;
}

#endif /* __linux__ */

#ifdef __linux__
int
ifaceGetVlanID(const char *vlanifname, int *vlanid) {
    struct vlan_ioctl_args vlanargs = {
      .cmd = GET_VLAN_VID_CMD,
    };
    int rc = 0;
    int fd = socket(PF_PACKET, SOCK_DGRAM, 0);

    if (fd < 0)
        return -errno;

    if (virStrcpyStatic(vlanargs.device1, vlanifname) == NULL) {
        rc = -EINVAL;
        goto cleanup;
    }

    if (ioctl(fd, SIOCGIFVLAN, &vlanargs) != 0) {
        rc = -errno;
        goto cleanup;
    }

    *vlanid = vlanargs.u.VID;

 cleanup:
    VIR_FORCE_CLOSE(fd);

    return rc;
}

#else

int
ifaceGetVlanID(const char *vlanifname ATTRIBUTE_UNUSED,
               int *vlanid ATTRIBUTE_UNUSED) {

    ifaceError(VIR_ERR_INTERNAL_ERROR, "%s",
               _("ifaceGetVlanID is not supported on non-linux platforms"));

    return -ENOSYS;
}
#endif /* __linux__ */


/**
 * ifaceGetIPAddress:
 * @ifname: name of the interface whose IP address we want
 * @macaddr: MAC address (VIR_MAC_BUFLEN in size)
 *
 * This function gets the @macaddr for a given interface @ifname.
 *
 * Returns 0 on success, -errno on failure.
 */
#ifdef __linux__
int
ifaceGetIPAddress(const char *ifname,
                  virSocketAddrPtr addr)
{
    struct ifreq ifr;
    int fd;
    int rc = 0;

    if (!ifname || !addr)
        return -EINVAL;

    memset (addr, 0, sizeof(*addr));
    addr->data.stor.ss_family = AF_UNSPEC;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -errno;

    memset(&ifr, 0, sizeof(struct ifreq));
    if (virStrcpyStatic(ifr.ifr_name, ifname) == NULL) {
        rc = -EINVAL;
        goto err_exit;
    }

    if (ioctl(fd, SIOCGIFADDR, (char *)&ifr) != 0) {
        rc = -errno;
        goto err_exit;
    }

    addr->data.stor.ss_family = AF_INET;
    addr->len = sizeof(addr->data.inet4);
    memcpy(&addr->data.inet4, &ifr.ifr_addr, addr->len);

err_exit:
    VIR_FORCE_CLOSE(fd);
    return rc;
}

#else

int
ifaceGetIPAddress(const char *ifname ATTRIBUTE_UNUSED,
                  virSocketAddrPtr addr ATTRIBUTE_UNUSED)
{
    return -ENOSYS;
}

#endif /* __linux__ */


#if defined(__linux__) && defined(IFLA_PORT_MAX)

static struct nla_policy ifla_policy[IFLA_MAX + 1] =
{
  [IFLA_VF_PORTS] = { .type = NLA_NESTED },
};

/**
 * ifaceMacvtapLinkDump
 *
 * @nltarget_kernel: whether to send the message to the kernel or another
 *                   process
 * @ifname: The name of the interface; only use if ifindex < 0
 * @ifindex: The interface index; may be < 0 if ifname is given
 * @nlattr: pointer to a pointer of netlink attributes that will contain
 *          the results
 * @recvbuf: Pointer to the buffer holding the returned netlink response
 *           message; free it, once not needed anymore
 * @getPidFunc: Pointer to a function that will be invoked if the kernel
 *              is not the target of the netlink message but it is to be
 *              sent to another process.
 *
 * Get information about an interface given its name or index.
 *
 * Returns 0 on success, -1 on fatal error.
 */
int
ifaceMacvtapLinkDump(bool nltarget_kernel, const char *ifname, int ifindex,
                     struct nlattr **tb, unsigned char **recvbuf,
                     uint32_t (*getPidFunc)(void))
{
    int rc = 0;
    struct nlmsghdr *resp;
    struct nlmsgerr *err;
    struct ifinfomsg ifinfo = {
        .ifi_family = AF_UNSPEC,
        .ifi_index  = ifindex
    };
    unsigned int recvbuflen;
    uint32_t pid = 0;
    struct nl_msg *nl_msg;

    *recvbuf = NULL;

    nl_msg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST);
    if (!nl_msg) {
        virReportOOMError();
        return -1;
    }

    if (nlmsg_append(nl_msg,  &ifinfo, sizeof(ifinfo), NLMSG_ALIGNTO) < 0)
        goto buffer_too_small;

    if (ifindex < 0 && ifname) {
        if (nla_put(nl_msg, IFLA_IFNAME, strlen(ifname)+1, ifname) < 0)
            goto buffer_too_small;
    }

    if (!nltarget_kernel) {
        pid = getPidFunc();
        if (pid == 0) {
            rc = -1;
            goto cleanup;
        }
    }

    if (nlComm(nl_msg, recvbuf, &recvbuflen, pid) < 0) {
        rc = -1;
        goto cleanup;
    }

    if (recvbuflen < NLMSG_LENGTH(0) || *recvbuf == NULL)
        goto malformed_resp;

    resp = (struct nlmsghdr *)*recvbuf;

    switch (resp->nlmsg_type) {
    case NLMSG_ERROR:
        err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (resp->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
            goto malformed_resp;

        if (err->error) {
            virReportSystemError(-err->error,
                                 _("error dumping %s (%d) interface"),
                                 ifname, ifindex);
            rc = -1;
        }
        break;

    case GENL_ID_CTRL:
    case NLMSG_DONE:
        if (nlmsg_parse(resp, sizeof(struct ifinfomsg),
                        tb, IFLA_MAX, ifla_policy)) {
            goto malformed_resp;
        }
        break;

    default:
        goto malformed_resp;
    }

    if (rc != 0)
        VIR_FREE(*recvbuf);

cleanup:
    nlmsg_free(nl_msg);

    return rc;

malformed_resp:
    nlmsg_free(nl_msg);

    ifaceError(VIR_ERR_INTERNAL_ERROR, "%s",
               _("malformed netlink response message"));
    VIR_FREE(*recvbuf);
    return -1;

buffer_too_small:
    nlmsg_free(nl_msg);

    ifaceError(VIR_ERR_INTERNAL_ERROR, "%s",
               _("allocated netlink buffer is too small"));
    return -1;
}

#else

int
ifaceMacvtapLinkDump(bool nltarget_kernel ATTRIBUTE_UNUSED,
                     const char *ifname ATTRIBUTE_UNUSED,
                     int ifindex ATTRIBUTE_UNUSED,
                     struct nlattr **tb ATTRIBUTE_UNUSED,
                     unsigned char **recvbuf ATTRIBUTE_UNUSED,
                     uint32_t (*getPidFunc)(void) ATTRIBUTE_UNUSED)
{
    ifaceError(VIR_ERR_INTERNAL_ERROR, "%s",
# if defined(__linux__) && !defined(IFLA_PORT_MAX)
               _("ifaceMacvtapLinkDump is not supported since the include "
                 "files were too old"));
# else
               _("ifaceMacvtapLinkDump is not supported on non-linux "
                 "platforms"));
# endif

    return -1;
}

#endif


/**
 * ifaceGetNthParent
 *
 * @ifindex : the index of the interface or -1 if ifname is given
 * @ifname : the name of the interface; ignored if ifindex is valid
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
#if defined(__linux__) && WITH_MACVTAP
int
ifaceGetNthParent(int ifindex, const char *ifname, unsigned int nthParent,
                  int *parent_ifindex, char *parent_ifname,
                  unsigned int *nth)
{
    int rc;
    struct nlattr *tb[IFLA_MAX + 1] = { NULL, };
    unsigned char *recvbuf = NULL;
    bool end = false;
    unsigned int i = 0;

    *nth = 0;

    if (ifindex <= 0 && ifaceGetIndex(true, ifname, &ifindex) < 0)
        return -1;

    while (!end && i <= nthParent) {
        rc = ifaceMacvtapLinkDump(true, ifname, ifindex, tb, &recvbuf, NULL);
        if (rc < 0)
            break;

        if (tb[IFLA_IFNAME]) {
            if (!virStrcpy(parent_ifname, (char*)RTA_DATA(tb[IFLA_IFNAME]),
                           IFNAMSIZ)) {
                ifaceError(VIR_ERR_INTERNAL_ERROR, "%s",
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

#else

int
ifaceGetNthParent(int ifindex ATTRIBUTE_UNUSED,
                  const char *ifname ATTRIBUTE_UNUSED,
                  unsigned int nthParent ATTRIBUTE_UNUSED,
                  int *parent_ifindex ATTRIBUTE_UNUSED,
                  char *parent_ifname ATTRIBUTE_UNUSED,
                  unsigned int *nth ATTRIBUTE_UNUSED)
{
    ifaceError(VIR_ERR_INTERNAL_ERROR, "%s",
# if defined(__linux__) && !WITH_MACVTAP
               _("ifaceGetNthParent is not supported since the include files "
                 "were too old"));
# else
               _("ifaceGetNthParent is not supported on non-linux platforms"));
# endif
    return -1;
}

#endif

/**
 * virNetDevReplaceMacAddress:
 * @macaddress: new MAC address for interface
 * @linkdev: name of interface
 * @stateDir: directory to store old MAC address
 *
 * Returns 0 on success, -1 on failure
 *
 */
int
virNetDevReplaceMacAddress(const char *linkdev,
                           const unsigned char *macaddress,
                           const char *stateDir)
{
    unsigned char oldmac[6];
    char *path = NULL;
    char macstr[VIR_MAC_STRING_BUFLEN];

    if (virNetDevGetMAC(linkdev, oldmac) < 0)
        return -1;


    if (virAsprintf(&path, "%s/%s",
                    stateDir,
                    linkdev) < 0) {
        virReportOOMError();
        return -1;
    }
    virFormatMacAddr(oldmac, macstr);
    if (virFileWriteStr(path, macstr, O_CREAT|O_TRUNC|O_WRONLY) < 0) {
        virReportSystemError(errno, _("Unable to preserve mac for %s"),
                             linkdev);
        return -1;
    }

    if (virNetDevSetMAC(linkdev, macaddress) < 0)
        return -1;

    return 0;
}

/**
 * virNetDevRestoreMacAddress:
 * @linkdev: name of interface
 * @stateDir: directory containing old MAC address
 *
 * Returns 0 on success, -errno on failure.
 *
 */
int
virNetDevRestoreMacAddress(const char *linkdev,
                           const char *stateDir)
{
    int rc;
    char *oldmacname = NULL;
    char *macstr = NULL;
    char *path = NULL;
    unsigned char oldmac[6];

    if (virAsprintf(&path, "%s/%s",
                    stateDir,
                    linkdev) < 0) {
        virReportOOMError();
        return -1;
    }

    if (virFileReadAll(path, VIR_MAC_STRING_BUFLEN, &macstr) < 0)
        return -1;

    if (virParseMacAddr(macstr, &oldmac[0]) != 0) {
        ifaceError(VIR_ERR_INTERNAL_ERROR,
                   _("Cannot parse MAC address from '%s'"),
                   oldmacname);
        VIR_FREE(macstr);
        return -1;
    }

    /*reset mac and remove file-ignore results*/
    rc = virNetDevSetMAC(linkdev, oldmac);
    ignore_value(unlink(path));
    VIR_FREE(macstr);

    return rc;
}

#ifdef __linux__
static int
ifaceSysfsFile(char **pf_sysfs_device_link, const char *ifname,
               const char *file)
{

    if (virAsprintf(pf_sysfs_device_link, NET_SYSFS "%s/%s",
        ifname, file) < 0) {
        virReportOOMError();
        return -1;
    }

    return 0;
}

static int
ifaceSysfsDeviceFile(char **pf_sysfs_device_link, const char *ifname,
                     const char *file)
{

    if (virAsprintf(pf_sysfs_device_link, NET_SYSFS "%s/device/%s",
        ifname, file) < 0) {
        virReportOOMError();
        return -1;
    }

    return 0;
}

/**
 * ifaceIsVirtualFunction
 *
 * @ifname : name of the interface
 *
 * Checks if an interface is a SRIOV virtual function.
 *
 * Returns 1 if interface is SRIOV virtual function, 0 if not and -1 if error
 *
 */
int
ifaceIsVirtualFunction(const char *ifname)
{
    char *if_sysfs_device_link = NULL;
    int ret = -1;

    if (ifaceSysfsFile(&if_sysfs_device_link, ifname, "device") < 0)
        return ret;

    ret = pciDeviceIsVirtualFunction(if_sysfs_device_link);

    VIR_FREE(if_sysfs_device_link);

    return ret;
}

/**
 * ifaceGetVirtualFunctionIndex
 *
 * @pfname : name of the physical function interface name
 * @vfname : name of the virtual function interface name
 * @vf_index : Pointer to int. Contains vf index of interface upon successful
 *             return
 *
 * Returns 0 on success, -1 on failure
 *
 */
int
ifaceGetVirtualFunctionIndex(const char *pfname, const char *vfname,
                             int *vf_index)
{
    char *pf_sysfs_device_link = NULL, *vf_sysfs_device_link = NULL;
    int ret = -1;

    if (ifaceSysfsFile(&pf_sysfs_device_link, pfname, "device") < 0)
        return ret;

    if (ifaceSysfsFile(&vf_sysfs_device_link, vfname, "device") < 0) {
        VIR_FREE(pf_sysfs_device_link);
        return ret;
    }

    ret = pciGetVirtualFunctionIndex(pf_sysfs_device_link,
                                     vf_sysfs_device_link,
                                     vf_index);

    VIR_FREE(pf_sysfs_device_link);
    VIR_FREE(vf_sysfs_device_link);

    return ret;
}

/**
 * ifaceGetPhysicalFunction
 *
 * @ifname : name of the physical function interface name
 * @pfname : Contains sriov physical function for interface ifname
 *           upon successful return
 *
 * Returns 0 on success, -1 on failure
 *
 */
int
ifaceGetPhysicalFunction(const char *ifname, char **pfname)
{
    char *physfn_sysfs_path = NULL;
    int ret = -1;

    if (ifaceSysfsDeviceFile(&physfn_sysfs_path, ifname, "physfn") < 0)
        return ret;

    ret = pciDeviceNetName(physfn_sysfs_path, pfname);

    VIR_FREE(physfn_sysfs_path);

    return ret;
}
#else
int
ifaceIsVirtualFunction(const char *ifname ATTRIBUTE_UNUSED)
{
    ifaceError(VIR_ERR_INTERNAL_ERROR, "%s",
               _("ifaceIsVirtualFunction is not supported on non-linux "
               "platforms"));
    return -1;
}

int
ifaceGetVirtualFunctionIndex(const char *pfname ATTRIBUTE_UNUSED,
                             const char *vfname ATTRIBUTE_UNUSED,
                             int *vf_index ATTRIBUTE_UNUSED)
{
    ifaceError(VIR_ERR_INTERNAL_ERROR, "%s",
               _("ifaceGetVirtualFunctionIndex is not supported on non-linux "
               "platforms"));
    return -1;
}

int
ifaceGetPhysicalFunction(const char *ifname ATTRIBUTE_UNUSED,
                         char **pfname ATTRIBUTE_UNUSED)
{
    ifaceError(VIR_ERR_INTERNAL_ERROR, "%s",
               _("ifaceGetPhysicalFunction is not supported on non-linux "
               "platforms"));
    return -1;
}
#endif /* __linux__ */
