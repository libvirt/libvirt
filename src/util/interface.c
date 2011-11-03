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
#include "logging.h"
#include "virnetdev.h"

#define VIR_FROM_THIS VIR_FROM_NET

#define ifaceError(code, ...) \
        virReportErrorHelper(VIR_FROM_NET, code, __FILE__, \
                             __FUNCTION__, __LINE__, __VA_ARGS__)


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

    if (ifindex <= 0 && virNetDevGetIndex(ifname, &ifindex) < 0)
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
