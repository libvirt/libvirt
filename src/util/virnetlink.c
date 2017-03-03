/*
 * Copyright (C) 2010-2016 Red Hat, Inc.
 * Copyright (C) 2010-2012, 2016 IBM Corporation
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
 *     Dirk Herrendoerfer <herrend[at]de[dot]ibm[dot]com>
 *
 * Notes:
 * netlink: http://lovezutto.googlepages.com/netlink.pdf
 *          iproute2 package
 *
 * 2012/02: Renamed from netlink.[ch] to virnetlink.[ch]
 *
 */

#include <config.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "virnetlink.h"
#include "virnetdev.h"
#include "virlog.h"
#include "viralloc.h"
#include "virthread.h"
#include "virmacaddr.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NET

VIR_LOG_INIT("util.netlink");

#define NETLINK_ACK_TIMEOUT_S  (2*1000)

#if defined(__linux__) && defined(HAVE_LIBNL)
/* State for a single netlink event handle */
struct virNetlinkEventHandle {
    int watch;
    virNetlinkEventHandleCallback handleCB;
    virNetlinkEventRemoveCallback removeCB;
    void *opaque;
    virMacAddr macaddr;
    int deleted;
};

# ifdef HAVE_LIBNL1
#  define virNetlinkAlloc nl_handle_alloc
#  define virNetlinkSetBufferSize nl_set_buffer_size
#  define virNetlinkFree nl_handle_destroy
typedef struct nl_handle virNetlinkHandle;
# else
#  define virNetlinkAlloc nl_socket_alloc
#  define virNetlinkSetBufferSize nl_socket_set_buffer_size
#  define virNetlinkFree nl_socket_free
typedef struct nl_sock virNetlinkHandle;
# endif

typedef struct _virNetlinkEventSrvPrivate virNetlinkEventSrvPrivate;
typedef virNetlinkEventSrvPrivate *virNetlinkEventSrvPrivatePtr;
struct _virNetlinkEventSrvPrivate {
    /*Server*/
    virMutex lock;
    int eventwatch;
    int netlinkfd;
    virNetlinkHandle *netlinknh;
    /*Events*/
    int handled;
    size_t handlesCount;
    size_t handlesAlloc;
    struct virNetlinkEventHandle *handles;
};

enum virNetlinkDeleteMode {
    VIR_NETLINK_HANDLE_VALID,
    VIR_NETLINK_HANDLE_DELETED,
};

/* Unique ID for the next netlink watch to be registered */
static int nextWatch = 1;

/* Allocate extra slots for virEventPollHandle/virEventPollTimeout
 records in this multiple */
# define NETLINK_EVENT_ALLOC_EXTENT 10

/* Linux kernel supports up to MAX_LINKS (32 at the time) individual
 * netlink protocols. */
static virNetlinkEventSrvPrivatePtr server[MAX_LINKS] = {NULL};
static virNetlinkHandle *placeholder_nlhandle;

/* Function definitions */

/**
 * virNetlinkStartup:
 *
 * Perform any initialization that needs to take place before the
 * program starts up worker threads. This is currently used to assure
 * that an nl_handle is allocated prior to any attempts to bind a
 * netlink socket. For a discussion of why this is necessary, please
 * see the following email message:
 *
 *   https://www.redhat.com/archives/libvir-list/2012-May/msg00202.html
 *
 * The short version is that, without this placeholder allocation of
 * an nl_handle that is never used, it is possible for nl_connect() in
 * one thread to collide with a direct bind() of a netlink socket in
 * another thread, leading to failure of the operation (which could
 * lead to failure of libvirtd to start). Since getaddrinfo() (used by
 * libvirtd in virSocketAddrParse, which is called quite frequently
 * during startup) directly calls bind() on a netlink socket, this is
 * actually a very common occurrence (15-20% failure rate on some
 * hardware).
 *
 * Returns 0 on success, -1 on failure.
 */
int
virNetlinkStartup(void)
{
    if (placeholder_nlhandle)
        return 0;
    VIR_DEBUG("Running global netlink initialization");
    placeholder_nlhandle = virNetlinkAlloc();
    if (!placeholder_nlhandle) {
        virReportSystemError(errno, "%s",
                             _("cannot allocate placeholder nlhandle for netlink"));
        return -1;
    }
    return 0;
}

/**
 * virNetlinkShutdown:
 *
 * Undo any initialization done by virNetlinkStartup. This currently
 * destroys the placeholder nl_handle.
 */
void
virNetlinkShutdown(void)
{
    if (placeholder_nlhandle) {
        virNetlinkFree(placeholder_nlhandle);
        placeholder_nlhandle = NULL;
    }
}


/**
 * virNetLinkCreateSocket:
 *
 * @protocol: which protocol to connect to (e.g. NETLINK_ROUTE,
 *
 * Create a netlink socket, set its buffer size, and turn on message
 * peeking (so the buffer size can be dynamically increased if
 * needed).
 *
 * Returns a handle to the new netlink socket, or 0 if there was a failure.
 *
 */
static virNetlinkHandle *
virNetlinkCreateSocket(int protocol)
{
    virNetlinkHandle *nlhandle = NULL;

    if (!(nlhandle = virNetlinkAlloc())) {
        virReportSystemError(errno, "%s",
                             _("cannot allocate nlhandle for netlink"));
        goto error;
    }
    if (nl_connect(nlhandle, protocol) < 0) {
        virReportSystemError(errno,
                             _("cannot connect to netlink socket "
                               "with protocol %d"), protocol);
        goto error;
    }

    if (virNetlinkSetBufferSize(nlhandle, 131702, 0) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot set netlink socket buffer "
                               "size to 128k"));
        goto error;
    }
    nl_socket_enable_msg_peek(nlhandle);

 cleanup:
    return nlhandle;

 error:
    if (nlhandle) {
        nl_close(nlhandle);
        virNetlinkFree(nlhandle);
        nlhandle = NULL;
    }
    goto cleanup;
}

static virNetlinkHandle *
virNetlinkSendRequest(struct nl_msg *nl_msg, uint32_t src_pid,
                      struct sockaddr_nl nladdr,
                      unsigned int protocol, unsigned int groups)
{
    ssize_t nbytes;
    int fd;
    int n;
    virNetlinkHandle *nlhandle = NULL;
    struct pollfd fds[1];
    struct nlmsghdr *nlmsg = nlmsg_hdr(nl_msg);

    if (protocol >= MAX_LINKS) {
        virReportSystemError(EINVAL,
                             _("invalid protocol argument: %d"), protocol);
        goto error;
    }

    if (!(nlhandle = virNetlinkCreateSocket(protocol)))
        goto error;

    fd = nl_socket_get_fd(nlhandle);
    if (fd < 0) {
        virReportSystemError(errno,
                             "%s", _("cannot get netlink socket fd"));
        goto error;
    }

    if (groups && nl_socket_add_membership(nlhandle, groups) < 0) {
        virReportSystemError(errno,
                             "%s", _("cannot add netlink membership"));
        goto error;
    }

    nlmsg_set_dst(nl_msg, &nladdr);

    nlmsg->nlmsg_pid = src_pid ? src_pid : getpid();

    nbytes = nl_send_auto_complete(nlhandle, nl_msg);
    if (nbytes < 0) {
        virReportSystemError(errno,
                             "%s", _("cannot send to netlink socket"));
        goto error;
    }

    memset(fds, 0, sizeof(fds));

    fds[0].fd = fd;
    fds[0].events = POLLIN;

    n = poll(fds, ARRAY_CARDINALITY(fds), NETLINK_ACK_TIMEOUT_S);
    if (n <= 0) {
        if (n < 0)
            virReportSystemError(errno, "%s",
                                 _("error in poll call"));
        if (n == 0)
            virReportSystemError(ETIMEDOUT, "%s",
                                 _("no valid netlink response was received"));
    }

    return nlhandle;

 error:
    virNetlinkFree(nlhandle);
    return NULL;
}

/**
 * virNetlinkCommand:
 * @nlmsg: pointer to netlink message
 * @respbuf: pointer to pointer where response buffer will be allocated
 * @respbuflen: pointer to integer holding the size of the response buffer
 *      on return of the function.
 * @src_pid: the pid of the process to send a message
 * @dst_pid: the pid of the process to talk to, i.e., pid = 0 for kernel
 * @protocol: netlink protocol
 * @groups: the group identifier
 *
 * Send the given message to the netlink layer and receive response.
 * Returns 0 on success, -1 on error. In case of error, no response
 * buffer will be returned.
 */
int virNetlinkCommand(struct nl_msg *nl_msg,
                      struct nlmsghdr **resp, unsigned int *respbuflen,
                      uint32_t src_pid, uint32_t dst_pid,
                      unsigned int protocol, unsigned int groups)
{
    int ret = -1;
    struct sockaddr_nl nladdr = {
            .nl_family = AF_NETLINK,
            .nl_pid    = dst_pid,
            .nl_groups = 0,
    };
    struct pollfd fds[1];
    virNetlinkHandle *nlhandle = NULL;
    int len = 0;

    memset(fds, 0, sizeof(fds));

    if (!(nlhandle = virNetlinkSendRequest(nl_msg, src_pid, nladdr,
                                           protocol, groups)))
        goto cleanup;

    len = nl_recv(nlhandle, &nladdr, (unsigned char **)resp, NULL);
    if (len == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("nl_recv failed - returned 0 bytes"));
        goto cleanup;
    }
    if (len < 0) {
        virReportSystemError(errno, "%s", _("nl_recv failed"));
        goto cleanup;
    }

    ret = 0;
    *respbuflen = len;
 cleanup:
    if (ret < 0) {
        *resp = NULL;
        *respbuflen = 0;
    }

    virNetlinkFree(nlhandle);
    return ret;
}

int
virNetlinkDumpCommand(struct nl_msg *nl_msg,
                      virNetlinkDumpCallback callback,
                      uint32_t src_pid, uint32_t dst_pid,
                      unsigned int protocol, unsigned int groups,
                      void *opaque)
{
    int ret = -1;
    bool end = false;
    int len = 0;
    struct nlmsghdr *resp = NULL;
    struct nlmsghdr *msg = NULL;

    struct sockaddr_nl nladdr = {
            .nl_family = AF_NETLINK,
            .nl_pid    = dst_pid,
            .nl_groups = 0,
    };
    virNetlinkHandle *nlhandle = NULL;

    if (!(nlhandle = virNetlinkSendRequest(nl_msg, src_pid, nladdr,
                                           protocol, groups)))
        goto cleanup;

    while (!end) {
        len = nl_recv(nlhandle, &nladdr, (unsigned char **)&resp, NULL);

        for (msg = resp; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
            if (msg->nlmsg_type == NLMSG_DONE)
                end = true;

            if (virNetlinkGetErrorCode(msg, len) < 0)
                goto cleanup;

            if (callback(msg, opaque) < 0)
                goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    virNetlinkFree(nlhandle);
    return ret;
}

/**
 * virNetlinkDumpLink:
 *
 * @ifname:  The name of the interface; only use if ifindex <= 0
 * @ifindex: The interface index; may be <= 0 if ifname is given
 * @data:    Gets a pointer to the raw data from netlink.
             MUST BE FREED BY CALLER!
 * @nlattr:  Pointer to a pointer of netlink attributes that will contain
 *           the results
 * @src_pid: pid used for nl_pid of the local end of the netlink message
 *           (0 == "use getpid()")
 * @dst_pid: pid of destination nl_pid if the kernel
 *           is not the target of the netlink message but it is to be
 *           sent to another process (0 if sending to the kernel)
 *
 * Get information from netlink about an interface given its name or index.
 *
 * Returns 0 on success, -1 on fatal error.
 */
int
virNetlinkDumpLink(const char *ifname, int ifindex,
                   void **nlData, struct nlattr **tb,
                   uint32_t src_pid, uint32_t dst_pid)
{
    int rc = -1;
    struct nlmsghdr *resp = NULL;
    struct nlmsgerr *err;
    struct ifinfomsg ifinfo = {
        .ifi_family = AF_UNSPEC,
        .ifi_index  = ifindex
    };
    unsigned int recvbuflen;
    struct nl_msg *nl_msg;

    if (ifname && ifindex <= 0 && virNetDevGetIndex(ifname, &ifindex) < 0)
        return -1;

    ifinfo.ifi_index = ifindex;

    nl_msg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST);
    if (!nl_msg) {
        virReportOOMError();
        return -1;
    }

    if (nlmsg_append(nl_msg,  &ifinfo, sizeof(ifinfo), NLMSG_ALIGNTO) < 0)
        goto buffer_too_small;

    if (ifname) {
        if (nla_put(nl_msg, IFLA_IFNAME, strlen(ifname)+1, ifname) < 0)
            goto buffer_too_small;
    }

# ifdef RTEXT_FILTER_VF
    /* if this filter exists in the kernel's netlink implementation,
     * we need to set it, otherwise the response message will not
     * contain the IFLA_VFINFO_LIST that we're looking for.
     */
    {
        uint32_t ifla_ext_mask = RTEXT_FILTER_VF;

        if (nla_put(nl_msg, IFLA_EXT_MASK,
                    sizeof(ifla_ext_mask), &ifla_ext_mask) < 0) {
            goto buffer_too_small;
        }
    }
# endif

    if (virNetlinkCommand(nl_msg, &resp, &recvbuflen,
                          src_pid, dst_pid, NETLINK_ROUTE, 0) < 0)
        goto cleanup;

    if (recvbuflen < NLMSG_LENGTH(0) || resp == NULL)
        goto malformed_resp;

    switch (resp->nlmsg_type) {
    case NLMSG_ERROR:
        err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (resp->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
            goto malformed_resp;

        if (err->error) {
            virReportSystemError(-err->error,
                                 _("error dumping %s (%d) interface"),
                                 ifname, ifindex);
            goto cleanup;
        }
        break;

    case GENL_ID_CTRL:
    case NLMSG_DONE:
        rc = nlmsg_parse(resp, sizeof(struct ifinfomsg),
                         tb, IFLA_MAX, NULL);
        if (rc < 0)
            goto malformed_resp;
        break;

    default:
        goto malformed_resp;
    }
    rc = 0;
 cleanup:
    nlmsg_free(nl_msg);
    if (rc < 0)
       VIR_FREE(resp);
    *nlData = resp;
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
 * virNetlinkDelLink:
 *
 * @ifname: Name of the link
 * @fallback: pointer to an alternate function that will
 *            be called to perform the delete if RTM_DELLINK fails
 *            with EOPNOTSUPP (any other error will simply be treated
 *            as an error).
 *
 * delete a network "link" (aka interface aka device) with the given
 * name. This works for many different types of network devices,
 * including macvtap and bridges.
 *
 * Returns 0 on success, -1 on fatal error.
 */
int
virNetlinkDelLink(const char *ifname, virNetlinkDelLinkFallback fallback)
{
    int rc = -1;
    struct nlmsghdr *resp = NULL;
    struct nlmsgerr *err;
    struct ifinfomsg ifinfo = { .ifi_family = AF_UNSPEC };
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

        if (-err->error == EOPNOTSUPP && fallback) {
            rc = fallback(ifname);
            goto cleanup;
        }
        if (err->error) {
            virReportSystemError(-err->error,
                                 _("error destroying network device %s"),
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


int
virNetlinkGetErrorCode(struct nlmsghdr *resp, unsigned int recvbuflen)
{
    struct nlmsgerr *err;
    int result = 0;

    if (recvbuflen < NLMSG_LENGTH(0) || resp == NULL)
        goto malformed_resp;

    switch (resp->nlmsg_type) {
    case NLMSG_ERROR:
        err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (resp->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
            goto malformed_resp;

        switch (err->error) {
        case 0: /* ACK */
            break;

        default:
            result = err->error;
        }
        break;

    case NLMSG_DONE:
        break;

    default:
        /* We allow multipart messages. */
        if (!(resp->nlmsg_flags & NLM_F_MULTI))
            goto malformed_resp;
    }

    return result;

 malformed_resp:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("malformed netlink response message"));
    return -EINVAL;
}


static void
virNetlinkEventServerLock(virNetlinkEventSrvPrivatePtr driver)
{
    virMutexLock(&driver->lock);
}

static void
virNetlinkEventServerUnlock(virNetlinkEventSrvPrivatePtr driver)
{
    virMutexUnlock(&driver->lock);
}

/**
 * virNetlinkEventRemoveClientPrimitive:
 *
 * @i: index of the client to remove from the table
 * @protocol: netlink protocol
 *
 * This static function does the low level removal of a client from
 * the table once its index is known, including calling the remove
 * callback (which usually will free resources required by the
 * handler). The event server lock *must* be locked before calling
 * this function.
 *
 * assumes success, returns nothing.
 */
static int
virNetlinkEventRemoveClientPrimitive(size_t i, unsigned int protocol)
{
    if (protocol >= MAX_LINKS)
        return -EINVAL;

    virNetlinkEventRemoveCallback removeCB = server[protocol]->handles[i].removeCB;

    if (removeCB) {
        (removeCB)(server[protocol]->handles[i].watch,
                   &server[protocol]->handles[i].macaddr,
                   server[protocol]->handles[i].opaque);
    }
    server[protocol]->handles[i].deleted = VIR_NETLINK_HANDLE_DELETED;
    return 0;
}

static void
virNetlinkEventCallback(int watch,
                        int fd ATTRIBUTE_UNUSED,
                        int events ATTRIBUTE_UNUSED,
                        void *opaque)
{
    virNetlinkEventSrvPrivatePtr srv = opaque;
    struct nlmsghdr *msg;
    struct sockaddr_nl peer;
    struct ucred *creds = NULL;
    size_t i;
    int length;
    bool handled = false;

    length = nl_recv(srv->netlinknh, &peer,
                     (unsigned char **)&msg, &creds);

    if (length == 0)
        return;
    if (length < 0) {
        virReportSystemError(errno,
                             "%s", _("nl_recv returned with error"));
        return;
    }

    virNetlinkEventServerLock(srv);

    VIR_DEBUG("dispatching to max %d clients, called from event watch %d",
            (int)srv->handlesCount, watch);

    for (i = 0; i < srv->handlesCount; i++) {
        if (srv->handles[i].deleted != VIR_NETLINK_HANDLE_VALID)
            continue;

        VIR_DEBUG("dispatching client %zu.", i);

        (srv->handles[i].handleCB)(msg, length, &peer, &handled,
                                   srv->handles[i].opaque);
    }

    if (!handled)
        VIR_DEBUG("event not handled.");
    VIR_FREE(msg);
    virNetlinkEventServerUnlock(srv);
}

/**
 * virNetlinkEventServiceStop:
 *
 * stop the monitor to receive netlink messages for libvirtd.
 * This removes the netlink socket fd from the event handler.
 *
 * @protocol: netlink protocol
 *
 * Returns -1 if the monitor cannot be unregistered, 0 upon success
 */
int
virNetlinkEventServiceStop(unsigned int protocol)
{
    if (protocol >= MAX_LINKS)
        return -EINVAL;

    virNetlinkEventSrvPrivatePtr srv = server[protocol];
    size_t i;

    VIR_INFO("stopping netlink event service");

    if (!server[protocol])
        return 0;

    virNetlinkEventServerLock(srv);
    nl_close(srv->netlinknh);
    virNetlinkFree(srv->netlinknh);
    virEventRemoveHandle(srv->eventwatch);

    /* free any remaining clients on the list */
    for (i = 0; i < srv->handlesCount; i++) {
        if (srv->handles[i].deleted == VIR_NETLINK_HANDLE_VALID)
            virNetlinkEventRemoveClientPrimitive(i, protocol);
    }

    server[protocol] = NULL;
    virNetlinkEventServerUnlock(srv);

    virMutexDestroy(&srv->lock);
    VIR_FREE(srv);
    return 0;
}

/**
 * virNetlinkEventServiceStopAll:
 *
 * Stop all the monitors to receive netlink messages for libvirtd.
 *
 * Returns -1 if any monitor cannot be unregistered, 0 upon success
 */
int
virNetlinkEventServiceStopAll(void)
{
    size_t i, j;
    virNetlinkEventSrvPrivatePtr srv = NULL;

    VIR_INFO("stopping all netlink event services");

    for (i = 0; i < MAX_LINKS; i++) {
        srv = server[i];
        if (!srv)
            continue;

        virNetlinkEventServerLock(srv);
        nl_close(srv->netlinknh);
        virNetlinkFree(srv->netlinknh);
        virEventRemoveHandle(srv->eventwatch);

        for (j = 0; j < srv->handlesCount; j++) {
            if (srv->handles[j].deleted == VIR_NETLINK_HANDLE_VALID)
                virNetlinkEventRemoveClientPrimitive(j, i);
        }

        server[i] = NULL;
        virNetlinkEventServerUnlock(srv);

        virMutexDestroy(&srv->lock);
        VIR_FREE(srv);
    }

    return 0;
}

/**
 * virNetlinkEventServiceIsRunning:
 *
 * Returns if the netlink event service is running.
 *
 * @protocol: netlink protocol
 *
 * Returns 'true' if the service is running, 'false' if stopped.
 */
bool
virNetlinkEventServiceIsRunning(unsigned int protocol)
{
    if (protocol >= MAX_LINKS) {
        virReportSystemError(EINVAL,
                             _("invalid protocol argument: %d"), protocol);
        return false;
    }

    return server[protocol] != NULL;
}

/**
 * virNetlinkEventServiceLocalPid:
 *
 * @protocol: netlink protocol
 *
 * Returns the nl_pid value that was used to bind() the netlink socket
 * used by the netlink event service, or -1 on error (netlink
 * guarantees that this value will always be > 0).
 */
int virNetlinkEventServiceLocalPid(unsigned int protocol)
{
    if (protocol >= MAX_LINKS)
        return -EINVAL;

    if (!(server[protocol] && server[protocol]->netlinknh)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("netlink event service not running"));
        return -1;
    }
    return (int)nl_socket_get_local_port(server[protocol]->netlinknh);
}


/**
 * virNetlinkEventServiceStart:
 *
 * start a monitor to receive netlink messages for libvirtd.
 * This registers a netlink socket with the event interface.
 *
 * @protocol: netlink protocol
 * @groups: broadcast groups to join in
 * Returns -1 if the monitor cannot be registered, 0 upon success
 */
int
virNetlinkEventServiceStart(unsigned int protocol, unsigned int groups)
{
    virNetlinkEventSrvPrivatePtr srv;
    int fd;
    int ret = -1;

    if (protocol >= MAX_LINKS) {
        virReportSystemError(EINVAL,
                             _("invalid protocol argument: %d"), protocol);
        return -EINVAL;
    }

    if (server[protocol])
        return 0;

    VIR_INFO("starting netlink event service with protocol %d", protocol);

    if (VIR_ALLOC(srv) < 0)
        return -1;

    if (virMutexInit(&srv->lock) < 0) {
        VIR_FREE(srv);
        return -1;
    }

    virNetlinkEventServerLock(srv);

    /* Allocate a new socket and get fd */
    if (!(srv->netlinknh = virNetlinkCreateSocket(protocol)))
        goto error_locked;

    fd = nl_socket_get_fd(srv->netlinknh);
    if (fd < 0) {
        virReportSystemError(errno,
                             "%s", _("cannot get netlink socket fd"));
        goto error_server;
    }

    if (groups && nl_socket_add_membership(srv->netlinknh, groups) < 0) {
        virReportSystemError(errno,
                             "%s", _("cannot add netlink membership"));
        goto error_server;
    }

    if (nl_socket_set_nonblocking(srv->netlinknh)) {
        virReportSystemError(errno, "%s",
                             _("cannot set netlink socket nonblocking"));
        goto error_server;
    }

    if ((srv->eventwatch = virEventAddHandle(fd,
                                             VIR_EVENT_HANDLE_READABLE,
                                             virNetlinkEventCallback,
                                             srv, NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to add netlink event handle watch"));
        goto error_server;
    }

    srv->netlinkfd = fd;
    VIR_DEBUG("netlink event listener on fd: %i running", fd);

    ret = 0;
    server[protocol] = srv;

 error_server:
    if (ret < 0) {
        nl_close(srv->netlinknh);
        virNetlinkFree(srv->netlinknh);
    }
 error_locked:
    virNetlinkEventServerUnlock(srv);
    if (ret < 0) {
        virMutexDestroy(&srv->lock);
        VIR_FREE(srv);
    }
    return ret;
}

/**
 * virNetlinkEventAddClient:
 *
 * @handleCB: callback to invoke when an event occurs
 * @removeCB: callback to invoke when removing a client
 * @opaque: user data to pass to callback
 * @macaddr: macaddr to store with the data. Used to identify callers.
 *           May be null.
 * @protocol: netlink protocol
 *
 * register a callback for handling of netlink messages. The
 * registered function receives the entire netlink message and
 * may choose to act upon it.
 *
 * Returns -1 if the file handle cannot be registered, number of
 * monitor upon success.
 */
int
virNetlinkEventAddClient(virNetlinkEventHandleCallback handleCB,
                         virNetlinkEventRemoveCallback removeCB,
                         void *opaque, const virMacAddr *macaddr,
                         unsigned int protocol)
{
    size_t i;
    int r, ret = -1;
    virNetlinkEventSrvPrivatePtr srv = NULL;

    if (protocol >= MAX_LINKS)
        return -EINVAL;

    srv = server[protocol];

    if (handleCB == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Invalid NULL callback provided"));
        return -1;
    }

    virNetlinkEventServerLock(srv);

    VIR_DEBUG("adding client: %d.", nextWatch);

    r = 0;
    /* first try to re-use deleted free slots */
    for (i = 0; i < srv->handlesCount; i++) {
        if (srv->handles[i].deleted == VIR_NETLINK_HANDLE_DELETED) {
            r = i;
            goto addentry;
        }
    }
    /* Resize the eventLoop array if needed */
    if (srv->handlesCount == srv->handlesAlloc) {
        VIR_DEBUG("Used %zu handle slots, adding at least %d more",
                  srv->handlesAlloc, NETLINK_EVENT_ALLOC_EXTENT);
        if (VIR_RESIZE_N(srv->handles, srv->handlesAlloc,
                        srv->handlesCount, NETLINK_EVENT_ALLOC_EXTENT) < 0)
            goto error;
    }
    r = srv->handlesCount++;

 addentry:
    srv->handles[r].watch    = nextWatch;
    srv->handles[r].handleCB = handleCB;
    srv->handles[r].removeCB = removeCB;
    srv->handles[r].opaque   = opaque;
    srv->handles[r].deleted  = VIR_NETLINK_HANDLE_VALID;
    if (macaddr)
        virMacAddrSet(&srv->handles[r].macaddr, macaddr);
    else
        virMacAddrSetRaw(&srv->handles[r].macaddr,
                         (unsigned char[VIR_MAC_BUFLEN]){0, 0, 0, 0, 0, 0});

    VIR_DEBUG("added client to loop slot: %d. with macaddr ptr=%p", r, macaddr);

    ret = nextWatch++;
 error:
    virNetlinkEventServerUnlock(srv);
    return ret;
}

/**
 * virNetlinkEventRemoveClient:
 *
 * @watch: watch whose handle to remove
 * @macaddr: macaddr whose handle to remove
 * @protocol: netlink protocol
 *
 * Unregister a callback from a netlink monitor.
 * The handler function referenced will no longer receive netlink messages.
 * Either watch or macaddr may be used, the other should be null.
 *
 * Returns -1 if the file handle was not registered, 0 upon success
 */
int
virNetlinkEventRemoveClient(int watch, const virMacAddr *macaddr,
                            unsigned int protocol)
{
    size_t i;
    int ret = -1;
    virNetlinkEventSrvPrivatePtr srv = NULL;

    if (protocol >= MAX_LINKS)
        return -EINVAL;

    srv = server[protocol];

    VIR_DEBUG("removing client watch=%d, mac=%p.", watch, macaddr);

    if (watch <= 0 && !macaddr) {
        VIR_WARN("Ignoring invalid netlink client id: %d", watch);
        return -1;
    }

    virNetlinkEventServerLock(srv);

    for (i = 0; i < srv->handlesCount; i++) {
        if (srv->handles[i].deleted != VIR_NETLINK_HANDLE_VALID)
            continue;

        if ((watch && srv->handles[i].watch == watch) ||
            (!watch &&
             virMacAddrCmp(macaddr, &srv->handles[i].macaddr) == 0)) {

            VIR_DEBUG("removed client: %d by %s.",
                      srv->handles[i].watch, watch ? "index" : "mac");
            virNetlinkEventRemoveClientPrimitive(i, protocol);
            ret = 0;
            goto cleanup;
        }
    }
    VIR_DEBUG("no client found to remove.");

 cleanup:
    virNetlinkEventServerUnlock(srv);
    return ret;
}

#else

# if defined(__linux)
static const char *unsupported = N_("libnl was not available at build time");
# else
static const char *unsupported = N_("not supported on non-linux platforms");
# endif

int
virNetlinkStartup(void)
{
    return 0;
}

void
virNetlinkShutdown(void)
{
    return;
}

int virNetlinkCommand(struct nl_msg *nl_msg ATTRIBUTE_UNUSED,
                      struct nlmsghdr **resp ATTRIBUTE_UNUSED,
                      unsigned int *respbuflen ATTRIBUTE_UNUSED,
                      uint32_t src_pid ATTRIBUTE_UNUSED,
                      uint32_t dst_pid ATTRIBUTE_UNUSED,
                      unsigned int protocol ATTRIBUTE_UNUSED,
                      unsigned int groups ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virNetlinkDumpCommand(struct nl_msg *nl_msg ATTRIBUTE_UNUSED,
                      virNetlinkDumpCallback callback ATTRIBUTE_UNUSED,
                      uint32_t src_pid ATTRIBUTE_UNUSED,
                      uint32_t dst_pid ATTRIBUTE_UNUSED,
                      unsigned int protocol ATTRIBUTE_UNUSED,
                      unsigned int groups ATTRIBUTE_UNUSED,
                      void *opaque ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virNetlinkDumpLink(const char *ifname ATTRIBUTE_UNUSED,
                   int ifindex ATTRIBUTE_UNUSED,
                   void **nlData ATTRIBUTE_UNUSED,
                   struct nlattr **tb ATTRIBUTE_UNUSED,
                   uint32_t src_pid ATTRIBUTE_UNUSED,
                   uint32_t dst_pid ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to dump link info on this platform"));
    return -1;
}


int
virNetlinkDelLink(const char *ifname ATTRIBUTE_UNUSED,
                  virNetlinkDelLinkFallback fallback ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

/**
 * stopNetlinkEventServer: stop the monitor to receive netlink
 * messages for libvirtd
 */
int virNetlinkEventServiceStop(unsigned int protocol ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("%s", _(unsupported));
    return 0;
}

/**
 * stopNetlinkEventServerAll: stop all the monitors to receive netlink
 * messages for libvirtd
 */
int virNetlinkEventServiceStopAll(void)
{
    VIR_DEBUG("%s", _(unsupported));
    return 0;
}

/**
 * startNetlinkEventServer: start a monitor to receive netlink
 * messages for libvirtd
 */
int virNetlinkEventServiceStart(unsigned int protocol ATTRIBUTE_UNUSED,
                                unsigned int groups ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("%s", _(unsupported));
    return 0;
}

/**
 * virNetlinkEventServiceIsRunning: returns if the netlink event
 * service is running.
 */
bool virNetlinkEventServiceIsRunning(unsigned int protocol ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return 0;
}

int virNetlinkEventServiceLocalPid(unsigned int protocol ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

/**
 * virNetlinkEventAddClient: register a callback for handling of
 * netlink messages
 */
int virNetlinkEventAddClient(virNetlinkEventHandleCallback handleCB ATTRIBUTE_UNUSED,
                             virNetlinkEventRemoveCallback removeCB ATTRIBUTE_UNUSED,
                             void *opaque ATTRIBUTE_UNUSED,
                             const virMacAddr *macaddr ATTRIBUTE_UNUSED,
                             unsigned int protocol ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

/**
 * virNetlinkEventRemoveClient: unregister a callback from a netlink monitor
 */
int virNetlinkEventRemoveClient(int watch ATTRIBUTE_UNUSED,
                                const virMacAddr *macaddr ATTRIBUTE_UNUSED,
                                unsigned int protocol ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}


int
virNetlinkGetErrorCode(struct nlmsghdr *resp ATTRIBUTE_UNUSED,
                       unsigned int recvbuflen ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -EINVAL;
}

#endif /* __linux__ */
