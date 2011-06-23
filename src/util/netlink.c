/*
 * Copyright (C) 2010-2011 Red Hat, Inc.
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

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include "netlink.h"
#include "memory.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_NET

#define netlinkError(code, ...)                                           \
        virReportErrorHelper(VIR_FROM_NET, code, __FILE__,                 \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

#define NETLINK_ACK_TIMEOUT_S  2

/**
 * nlComm:
 * @nlmsg: pointer to netlink message
 * @respbuf: pointer to pointer where response buffer will be allocated
 * @respbuflen: pointer to integer holding the size of the response buffer
 *      on return of the function.
 * @nl_pid: the pid of the process to talk to, i.e., pid = 0 for kernel
 *
 * Send the given message to the netlink layer and receive response.
 * Returns 0 on success, -1 on error. In case of error, no response
 * buffer will be returned.
 */
#if defined(__linux__) && defined(HAVE_LIBNL)
int nlComm(struct nl_msg *nl_msg,
           unsigned char **respbuf, unsigned int *respbuflen,
           int nl_pid)
{
    int rc = 0;
    struct sockaddr_nl nladdr = {
            .nl_family = AF_NETLINK,
            .nl_pid    = nl_pid,
            .nl_groups = 0,
    };
    ssize_t nbytes;
    struct timeval tv = {
        .tv_sec = NETLINK_ACK_TIMEOUT_S,
    };
    fd_set readfds;
    int fd;
    int n;
    struct nlmsghdr *nlmsg = nlmsg_hdr(nl_msg);
    struct nl_handle *nlhandle = nl_handle_alloc();

    if (!nlhandle) {
        virReportSystemError(errno,
                             "%s", _("cannot allocate nlhandle for netlink"));
        return -1;
    }

    if (nl_connect(nlhandle, NETLINK_ROUTE) < 0) {
        virReportSystemError(errno,
                             "%s", _("cannot connect to netlink socket"));
        rc = -1;
        goto err_exit;
    }

    nlmsg_set_dst(nl_msg, &nladdr);

    nlmsg->nlmsg_pid = getpid();

    nbytes = nl_send_auto_complete(nlhandle, nl_msg);
    if (nbytes < 0) {
        virReportSystemError(errno,
                             "%s", _("cannot send to netlink socket"));
        rc = -1;
        goto err_exit;
    }

    fd = nl_socket_get_fd(nlhandle);

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    n = select(fd + 1, &readfds, NULL, NULL, &tv);
    if (n <= 0) {
        if (n < 0)
            virReportSystemError(errno, "%s",
                                 _("error in select call"));
        if (n == 0)
            virReportSystemError(ETIMEDOUT, "%s",
                                 _("no valid netlink response was received"));
        rc = -1;
        goto err_exit;
    }

    *respbuflen = nl_recv(nlhandle, &nladdr, respbuf, NULL);
    if (*respbuflen <= 0) {
        virReportSystemError(errno,
                             "%s", _("nl_recv failed"));
        rc = -1;
    }
err_exit:
    if (rc == -1) {
        VIR_FREE(*respbuf);
        *respbuf = NULL;
        *respbuflen = 0;
    }

    nl_handle_destroy(nlhandle);
    return rc;
}

#else

int nlComm(struct nl_msg *nl_msg ATTRIBUTE_UNUSED,
           unsigned char **respbuf ATTRIBUTE_UNUSED,
           unsigned int *respbuflen ATTRIBUTE_UNUSED,
           int nl_pid ATTRIBUTE_UNUSED)
{
    netlinkError(VIR_ERR_INTERNAL_ERROR, "%s",
# if defined(__linux__) && !defined(HAVE_LIBNL)
                 _("nlComm is not supported since libnl was not available"));
# else
                 _("nlComm is not supported on non-linux platforms"));
# endif
    return -1;
}

#endif /* __linux__ */
